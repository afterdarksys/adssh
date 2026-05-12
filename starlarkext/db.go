package starlarkext

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"go.starlark.net/starlark"
)

// SetupDatabaseAPI registers the db.* namespace into the Starlark environment.
//
// Starlark API:
//
//	conn = db.postgres.connect("postgres://user:pass@host:5432/dbname")
//	conn = db.mysql.connect("user:pass@tcp(host:3306)/dbname")
//
//	rows = conn.query("SELECT id, name FROM users WHERE active = $1", [True])
//	# Returns list of dicts: [{"id": 1, "name": "Alice"}, ...]
//
//	result = conn.exec("INSERT INTO users (name) VALUES ($1)", ["Bob"])
//	# Returns {"rows_affected": 1}
//
//	conn.close()
//
//	r = db.redis.connect("localhost:6379", password="", db=0)
//	r.set("key", "value", ex=300)   # ex = TTL in seconds (0 = no expiry)
//	val = r.get("key")
//	r.del("key")
//	keys = r.keys("prefix:*")
//	r.hset("hash", "field", "value")
//	val = r.hget("hash", "field")
//	all = r.hgetall("hash")         # returns dict
//	r.lpush("list", ["a", "b"])
//	items = r.lrange("list", 0, -1)
//	r.publish("channel", "message")
//	r.close()
func SetupDatabaseAPI(env starlark.StringDict) {
	postgresDict := starlark.NewDict(1)
	postgresDict.SetKey(starlark.String("connect"), starlark.NewBuiltin("connect", dbPostgresConnect))

	mysqlDict := starlark.NewDict(1)
	mysqlDict.SetKey(starlark.String("connect"), starlark.NewBuiltin("connect", dbMySQLConnect))

	redisDict := starlark.NewDict(1)
	redisDict.SetKey(starlark.String("connect"), starlark.NewBuiltin("connect", dbRedisConnect))

	d := starlark.NewDict(3)
	d.SetKey(starlark.String("postgres"), postgresDict)
	d.SetKey(starlark.String("mysql"), mysqlDict)
	d.SetKey(starlark.String("redis"), redisDict)
	env["db"] = d
}

// ── SQL Connection (Postgres + MySQL share this type) ─────────────────────────

type dbConn struct {
	db     *sql.DB
	driver string
	mu     sync.Mutex
	closed bool
}

var _ starlark.HasAttrs = (*dbConn)(nil)

func (c *dbConn) String() string        { return fmt.Sprintf("<db.conn:%s>", c.driver) }
func (c *dbConn) Type() string          { return "db.conn" }
func (c *dbConn) Freeze()               {}
func (c *dbConn) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: db.conn") }
func (c *dbConn) Truth() starlark.Bool  { return starlark.Bool(!c.closed) }

func (c *dbConn) Attr(name string) (starlark.Value, error) {
	switch name {
	case "query":
		return starlark.NewBuiltin("query", c.builtinQuery), nil
	case "exec":
		return starlark.NewBuiltin("exec", c.builtinExec), nil
	case "close":
		return starlark.NewBuiltin("close", c.builtinClose), nil
	}
	return nil, nil
}

func (c *dbConn) AttrNames() []string {
	return []string{"close", "exec", "query"}
}

func (c *dbConn) builtinQuery(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var query string
	var params *starlark.List
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "sql", &query, "params?", &params); err != nil {
		return nil, err
	}
	sqlParams := starlarkListToGoSlice(params)
	rows, err := c.db.QueryContext(context.Background(), query, sqlParams...)
	if err != nil {
		return nil, fmt.Errorf("db.query: %v", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("db.query columns: %v", err)
	}

	result := starlark.NewList(nil)
	vals := make([]interface{}, len(cols))
	ptrs := make([]interface{}, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return nil, fmt.Errorf("db.query scan: %v", err)
		}
		row := starlark.NewDict(len(cols))
		for i, col := range cols {
			row.SetKey(starlark.String(col), sqlValueToStarlark(vals[i]))
		}
		result.Append(row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db.query rows: %v", err)
	}
	return result, nil
}

func (c *dbConn) builtinExec(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var query string
	var params *starlark.List
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "sql", &query, "params?", &params); err != nil {
		return nil, err
	}
	sqlParams := starlarkListToGoSlice(params)
	res, err := c.db.ExecContext(context.Background(), query, sqlParams...)
	if err != nil {
		return nil, fmt.Errorf("db.exec: %v", err)
	}
	affected, _ := res.RowsAffected()
	return makeDict("rows_affected", affected), nil
}

func (c *dbConn) builtinClose(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.db.Close()
		c.closed = true
	}
	return starlark.None, nil
}

func dbPostgresConnect(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var dsn string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "dsn", &dsn); err != nil {
		return nil, err
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("db.postgres.connect: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("db.postgres.connect: %v", err)
	}
	return &dbConn{db: db, driver: "postgres"}, nil
}

func dbMySQLConnect(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var dsn string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "dsn", &dsn); err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("db.mysql.connect: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("db.mysql.connect: %v", err)
	}
	return &dbConn{db: db, driver: "mysql"}, nil
}

// ── Redis Connection ──────────────────────────────────────────────────────────

type redisConn struct {
	client *redis.Client
	mu     sync.Mutex
	closed bool
}

var _ starlark.HasAttrs = (*redisConn)(nil)

func (r *redisConn) String() string        { return "<db.redis>" }
func (r *redisConn) Type() string          { return "db.redis" }
func (r *redisConn) Freeze()               {}
func (r *redisConn) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: db.redis") }
func (r *redisConn) Truth() starlark.Bool  { return starlark.Bool(!r.closed) }

func (r *redisConn) Attr(name string) (starlark.Value, error) {
	switch name {
	case "get":
		return starlark.NewBuiltin("get", r.builtinGet), nil
	case "set":
		return starlark.NewBuiltin("set", r.builtinSet), nil
	case "del":
		return starlark.NewBuiltin("del", r.builtinDel), nil
	case "keys":
		return starlark.NewBuiltin("keys", r.builtinKeys), nil
	case "hget":
		return starlark.NewBuiltin("hget", r.builtinHGet), nil
	case "hset":
		return starlark.NewBuiltin("hset", r.builtinHSet), nil
	case "hgetall":
		return starlark.NewBuiltin("hgetall", r.builtinHGetAll), nil
	case "lpush":
		return starlark.NewBuiltin("lpush", r.builtinLPush), nil
	case "lrange":
		return starlark.NewBuiltin("lrange", r.builtinLRange), nil
	case "publish":
		return starlark.NewBuiltin("publish", r.builtinPublish), nil
	case "close":
		return starlark.NewBuiltin("close", r.builtinClose), nil
	}
	return nil, nil
}

func (r *redisConn) AttrNames() []string {
	return []string{"close", "del", "get", "hget", "hgetall", "hset", "keys", "lpush", "lrange", "publish", "set"}
}

func dbRedisConnect(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr, password string
	var db int
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "addr?", &addr, "password?", &password, "db?", &db); err != nil {
		return nil, err
	}
	if addr == "" {
		addr = "localhost:6379"
	}
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	if err := client.Ping(context.Background()).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("db.redis.connect: %v", err)
	}
	return &redisConn{client: client}, nil
}

func (r *redisConn) builtinGet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key); err != nil {
		return nil, err
	}
	val, err := r.client.Get(context.Background(), key).Result()
	if err == redis.Nil {
		return starlark.None, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis.get: %v", err)
	}
	return starlark.String(val), nil
}

func (r *redisConn) builtinSet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key, value string
	var ex int // TTL seconds; 0 = no expiry
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key, "value", &value, "ex?", &ex); err != nil {
		return nil, err
	}
	expiry := time.Duration(ex) * time.Second
	if err := r.client.Set(context.Background(), key, value, expiry).Err(); err != nil {
		return nil, fmt.Errorf("redis.set: %v", err)
	}
	return starlark.None, nil
}

func (r *redisConn) builtinDel(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key); err != nil {
		return nil, err
	}
	if err := r.client.Del(context.Background(), key).Err(); err != nil {
		return nil, fmt.Errorf("redis.del: %v", err)
	}
	return starlark.None, nil
}

func (r *redisConn) builtinKeys(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	pattern := "*"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "pattern?", &pattern); err != nil {
		return nil, err
	}
	keys, err := r.client.Keys(context.Background(), pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("redis.keys: %v", err)
	}
	return toStarlark(keys), nil
}

func (r *redisConn) builtinHGet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key, field string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key, "field", &field); err != nil {
		return nil, err
	}
	val, err := r.client.HGet(context.Background(), key, field).Result()
	if err == redis.Nil {
		return starlark.None, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis.hget: %v", err)
	}
	return starlark.String(val), nil
}

func (r *redisConn) builtinHSet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key, field, value string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key, "field", &field, "value", &value); err != nil {
		return nil, err
	}
	if err := r.client.HSet(context.Background(), key, field, value).Err(); err != nil {
		return nil, fmt.Errorf("redis.hset: %v", err)
	}
	return starlark.None, nil
}

func (r *redisConn) builtinHGetAll(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key); err != nil {
		return nil, err
	}
	m, err := r.client.HGetAll(context.Background(), key).Result()
	if err != nil {
		return nil, fmt.Errorf("redis.hgetall: %v", err)
	}
	return toStarlark(m), nil
}

func (r *redisConn) builtinLPush(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	var values *starlark.List
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key, "values", &values); err != nil {
		return nil, err
	}
	goVals := starlarkListToGoSlice(values)
	if err := r.client.LPush(context.Background(), key, goVals...).Err(); err != nil {
		return nil, fmt.Errorf("redis.lpush: %v", err)
	}
	return starlark.None, nil
}

func (r *redisConn) builtinLRange(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	var start, stop int
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key, "start?", &start, "stop?", &stop); err != nil {
		return nil, err
	}
	items, err := r.client.LRange(context.Background(), key, int64(start), int64(stop)).Result()
	if err != nil {
		return nil, fmt.Errorf("redis.lrange: %v", err)
	}
	return toStarlark(items), nil
}

func (r *redisConn) builtinPublish(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var channel, message string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "channel", &channel, "message", &message); err != nil {
		return nil, err
	}
	if err := r.client.Publish(context.Background(), channel, message).Err(); err != nil {
		return nil, fmt.Errorf("redis.publish: %v", err)
	}
	return starlark.None, nil
}

func (r *redisConn) builtinClose(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.client.Close()
		r.closed = true
	}
	return starlark.None, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// starlarkListToGoSlice converts a *starlark.List to []interface{}.
func starlarkListToGoSlice(list *starlark.List) []interface{} {
	if list == nil {
		return nil
	}
	out := make([]interface{}, list.Len())
	for i := 0; i < list.Len(); i++ {
		out[i] = starlarkValueToGo(list.Index(i))
	}
	return out
}

// sqlValueToStarlark converts a sql.Scan result value to a Starlark value.
// sql.Scan returns nil, int64, float64, bool, []byte, string, or time.Time.
func sqlValueToStarlark(v interface{}) starlark.Value {
	if v == nil {
		return starlark.None
	}
	switch val := v.(type) {
	case int64:
		return starlark.MakeInt64(val)
	case float64:
		return starlark.Float(val)
	case bool:
		return starlark.Bool(val)
	case []byte:
		return starlark.String(string(val))
	case string:
		return starlark.String(val)
	default:
		return starlark.String(fmt.Sprintf("%v", val))
	}
}

