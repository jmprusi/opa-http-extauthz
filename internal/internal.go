// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	//ext_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	//ext_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/plugins/logs"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/server"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/topdown"
	iCache "github.com/open-policy-agent/opa/topdown/cache"
	"github.com/open-policy-agent/opa/util"
	"github.com/sirupsen/logrus"
)

const defaultAddr = ":9292"
const defaultPath = "envoy/authz/allow"
const defaultDryRun = false
const defaultEnableReflection = false

// PluginName is the name to register with the OPA plugin manager
const PluginName = "envoy_ext_authz_http"

var revisionPath = storage.MustParsePath("/system/bundle/manifest/revision")

type evalResult struct {
	revision   string
	decisionID string
	txnID      uint64
	decision   interface{}
	metrics    metrics.Metrics
}

// Validate receives a slice of bytes representing the plugin's
// configuration and returns a configuration value that can be used to
// instantiate the plugin.
func Validate(m *plugins.Manager, bs []byte) (*Config, error) {

	cfg := Config{
		Addr:   defaultAddr,
		DryRun: defaultDryRun,
	}

	if err := util.Unmarshal(bs, &cfg); err != nil {
		return nil, err
	}

	if cfg.Path != "" && cfg.Query != "" {
		return nil, fmt.Errorf("invalid config: specify a value for only the \"path\" field")
	}

	var parsedQuery ast.Body
	var err error

	if cfg.Query != "" {
		// Deprecated: Use Path instead
		parsedQuery, err = ast.ParseBody(cfg.Query)
	} else {
		if cfg.Path == "" {
			cfg.Path = defaultPath
		}
		path := stringPathToDataRef(cfg.Path)
		parsedQuery, err = ast.ParseBody(path.String())
	}

	if err != nil {
		return nil, err
	}

	cfg.parsedQuery = parsedQuery

	return &cfg, nil
}

func (p *envoyExtAuthzHTTPServer) Check(w http.ResponseWriter, r *http.Request) {

	var err error
	//start := time.Now()

	ctx := r.Context()
	result := evalResult{}
	result.metrics = metrics.New()
	result.metrics.Timer(metrics.ServerHandler).Start()

	result.decisionID, err = uuid4()

	if err != nil {
		logrus.WithField("err", err).Error("Unable to generate decision ID.")
		w.WriteHeader(503)
		return
	}

	if ctx.Err() != nil {
		err = errors.Wrap(ctx.Err(), "check request timed out before query execution")
		w.WriteHeader(503)
		return
	}

	input := make(map[string]interface{}, 0)
	path, query, err := getParsedPathAndQuery(r.RequestURI)
	if err != nil {
		w.WriteHeader(503)
		return
	}

	attributes := make(map[string]interface{}, 0)
	request := make(map[string]interface{}, 0)
	http := make(map[string]interface{}, 0)

	// Check other implementations and try to match the attributes
	http["method"] = r.Method
	http["path"] = r.RequestURI
	http["host"] = r.Host
	http["parsed_path"] = path
	http["parsed_query"] = query

	// Do it in a nicer way.
	request["http"] = http
	attributes["request"] = request
	input["attributes"] = attributes

	inputValue, err := ast.InterfaceToValue(input)
	if err != nil {
		w.WriteHeader(503)
		return
	}

	err = p.eval(ctx, inputValue, &result)
	if err != nil {
		w.WriteHeader(503)
		return

	}

	switch decision := result.decision.(type) {
	case bool:
		if decision {
			w.WriteHeader(200)
			return
		} else {
			w.WriteHeader(403)
			return
		}

	default:
		err = fmt.Errorf("illegal value for policy evaluation result: %T", decision)
		w.WriteHeader(503)
		return
	}

}

// New returns a Plugin that implements the Envoy ext_authz API.
func New(m *plugins.Manager, cfg *Config) plugins.Plugin {

	s := &http.Server{
		Addr: ":9292",
	}

	plugin := &envoyExtAuthzHTTPServer{
		manager:                m,
		cfg:                    *cfg,
		HTTPServer:             s,
		preparedQueryDoOnce:    new(sync.Once),
		interQueryBuiltinCache: iCache.NewInterQueryCache(m.InterQueryBuiltinCacheConfig()),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", plugin.Check)
	plugin.HTTPServer.Handler = mux

	m.RegisterCompilerTrigger(plugin.compilerUpdated)

	m.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})

	return plugin
}

// Config represents the plugin configuration.
type Config struct {
	Addr        string `json:"addr"`
	Query       string `json:"query"` // Deprecated: Use Path instead
	Path        string `json:"path"`
	DryRun      bool   `json:"dry-run"`
	parsedQuery ast.Body
}

type envoyExtAuthzHTTPServer struct {
	cfg                    Config
	HTTPServer             *http.Server
	manager                *plugins.Manager
	preparedQuery          *rego.PreparedEvalQuery
	preparedQueryDoOnce    *sync.Once
	interQueryBuiltinCache iCache.InterQueryCache
}

func (p *envoyExtAuthzHTTPServer) Start(ctx context.Context) error {
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
	go func() {
		if err := p.HTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return
		}
	}()
	return nil
}

func (p *envoyExtAuthzHTTPServer) Stop(ctx context.Context) {
	p.HTTPServer.Shutdown(ctx)
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
}

func (p *envoyExtAuthzHTTPServer) Reconfigure(ctx context.Context, config interface{}) {
	return
}

func (p *envoyExtAuthzHTTPServer) compilerUpdated(txn storage.Transaction) {
	p.preparedQueryDoOnce = new(sync.Once)
}

func (p *envoyExtAuthzHTTPServer) listen() {
	l, err := net.Listen("tcp", p.cfg.Addr)

	err = http.Serve(l, nil)
	if err != nil {
		logrus.WithField("err", err).Fatal("Unable to create listener.")
	}

	logrus.WithFields(logrus.Fields{
		"addr":    p.cfg.Addr,
		"query":   p.cfg.Query,
		"path":    p.cfg.Path,
		"dry-run": p.cfg.DryRun,
	}).Info("Starting gRPC HTTPServer.")

	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateOK})

	if err := p.HTTPServer.Serve(l); err != nil {
		logrus.WithField("err", err).Fatal("Listener failed.")
	}

	logrus.Info("Listener exited.")
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})

}

func (p *envoyExtAuthzHTTPServer) eval(ctx context.Context, input ast.Value, result *evalResult, opts ...func(*rego.Rego)) error {

	err := storage.Txn(ctx, p.manager.Store, storage.TransactionParams{}, func(txn storage.Transaction) error {

		var err error

		result.revision, err = getRevision(ctx, p.manager.Store, txn)
		if err != nil {
			return err
		}

		result.txnID = txn.ID()

		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.WithFields(logrus.Fields{
				"input":   input,
				"query":   p.cfg.parsedQuery.String(),
				"dry-run": p.cfg.DryRun,
				"txn":     result.txnID,
			}).Debug("Executing policy query.")
		}

		err = p.constructPreparedQuery(txn, result.metrics, opts)
		if err != nil {
			return err
		}

		rs, err := p.preparedQuery.Eval(
			ctx,
			rego.EvalParsedInput(input),
			rego.EvalTransaction(txn),
			rego.EvalMetrics(result.metrics),
			rego.EvalInterQueryBuiltinCache(p.interQueryBuiltinCache),
		)

		if err != nil {
			return err
		} else if len(rs) == 0 {
			return fmt.Errorf("undefined decision")
		} else if len(rs) > 1 {
			return fmt.Errorf("multiple evaluation results")
		}

		result.decision = rs[0].Expressions[0].Value
		return nil
	})

	return err
}

func (p *envoyExtAuthzHTTPServer) constructPreparedQuery(txn storage.Transaction, m metrics.Metrics, opts []func(*rego.Rego)) error {
	var err error
	var pq rego.PreparedEvalQuery

	p.preparedQueryDoOnce.Do(func() {
		opts = append(opts,
			rego.Metrics(m),
			rego.ParsedQuery(p.cfg.parsedQuery),
			rego.Compiler(p.manager.GetCompiler()),
			rego.Store(p.manager.Store),
			rego.Transaction(txn),
			rego.Runtime(p.manager.Info))

		r := rego.New(opts...)

		pq, err = r.PrepareForEval(context.Background())
		p.preparedQuery = &pq
	})

	return err
}

func (p *envoyExtAuthzHTTPServer) log(ctx context.Context, input interface{}, result *evalResult, err error) error {
	plugin := logs.Lookup(p.manager)
	if plugin == nil {
		return nil
	}

	info := &server.Info{
		Timestamp: time.Now(),
		Input:     &input,
	}

	if p.cfg.Query != "" {
		info.Query = p.cfg.Query
	}

	if p.cfg.Path != "" {
		info.Path = p.cfg.Path
	}

	info.Revision = result.revision
	info.DecisionID = result.decisionID
	info.Metrics = result.metrics

	if err != nil {
		switch err.(type) {
		case *storage.Error, *ast.Error, ast.Errors:
			break
		case *topdown.Error:
			if topdown.IsCancel(err) {
				err = &topdown.Error{
					Code:    topdown.CancelErr,
					Message: "context deadline reached during query execution",
				}
			}
		default:
			// Wrap errors that may not serialize to JSON well (e.g., fmt.Errorf, etc.)
			err = &internalError{Message: err.Error()}
		}
		info.Error = err
	} else {
		var x interface{}
		if result != nil {
			x = result.decision
		}
		info.Results = &x
	}

	return plugin.Log(ctx, info)
}

func uuid4() (string, error) {
	bs := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, bs)
	if n != len(bs) || err != nil {
		return "", err
	}
	bs[8] = bs[8]&^0xc0 | 0x80
	bs[6] = bs[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", bs[0:4], bs[4:6], bs[6:8], bs[8:10], bs[10:]), nil
}

func getRevision(ctx context.Context, store storage.Store, txn storage.Transaction) (string, error) {
	value, err := store.Read(ctx, txn, revisionPath)
	if err != nil {
		if storage.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}
	revision, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("bad revision")
	}
	return revision, nil
}

func getParsedPathAndQuery(path string) ([]interface{}, map[string]interface{}, error) {
	unescapedPath, err := url.PathUnescape(path)
	if err != nil {
		return nil, nil, err
	}

	parsedURL, err := url.Parse(unescapedPath)
	if err != nil {
		return nil, nil, err
	}

	parsedPath := strings.Split(strings.TrimLeft(parsedURL.Path, "/"), "/")
	parsedPathInterface := make([]interface{}, len(parsedPath))
	for i, v := range parsedPath {
		parsedPathInterface[i] = v
	}

	parsedQueryInterface := make(map[string]interface{})
	for paramKey, paramValues := range parsedURL.Query() {
		queryValues := make([]interface{}, len(paramValues))
		for i, v := range paramValues {
			queryValues[i] = v
		}
		parsedQueryInterface[paramKey] = queryValues
	}

	return parsedPathInterface, parsedQueryInterface, nil
}

func getParsedBody(headers map[string]string, body string) (interface{}, bool, error) {
	if body == "" {
		return nil, false, nil
	}

	if val, ok := headers["content-length"]; ok {
		cl, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return nil, false, err
		}

		if cl != -1 && cl > int64(len(body)) {
			return nil, true, nil
		}
	}

	var data interface{}

	if val, ok := headers["content-type"]; ok {
		if strings.Contains(val, "application/json") {
			err := util.Unmarshal([]byte(body), &data)
			if err != nil {
				return nil, false, err
			}
		}
	}

	return data, false, nil
}

func stringPathToDataRef(s string) (r ast.Ref) {
	result := ast.Ref{ast.DefaultRootDocument}
	result = append(result, stringPathToRef(s)...)
	return result
}

func stringPathToRef(s string) (r ast.Ref) {
	if len(s) == 0 {
		return r
	}

	p := strings.Split(s, "/")
	for _, x := range p {
		if x == "" {
			continue
		}

		i, err := strconv.Atoi(x)
		if err != nil {
			r = append(r, ast.StringTerm(x))
		} else {
			r = append(r, ast.IntNumberTerm(i))
		}
	}
	return r
}

type internalError struct {
	Message string `json:"message"`
}

func (e *internalError) Error() string {
	return e.Message
}
