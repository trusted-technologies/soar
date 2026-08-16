package router

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/pterodactyl/wings/databasehost"
	"github.com/pterodactyl/wings/l4"
	"github.com/pterodactyl/wings/l7"
	"github.com/pterodactyl/wings/router/middleware"
	"github.com/pterodactyl/wings/system"
	"github.com/pterodactyl/wings/updater"
)

func soarError(c *gin.Context, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, databasehost.ErrInvalidRequest):
		status = http.StatusUnprocessableEntity
	case errors.Is(err, databasehost.ErrUnsupported), errors.Is(err, databasehost.ErrDatabaseMissing), errors.Is(err, databasehost.ErrNotInstalled):
		status = http.StatusNotFound
	case errors.Is(err, databasehost.ErrDatabaseExists), errors.Is(err, databasehost.ErrEngineInUse):
		status = http.StatusConflict
	}
	c.AbortWithStatusJSON(status, gin.H{"error": err.Error()})
}

func getSoarInformation(c *gin.Context) {
	databases := databasehost.Default().List(c.Request.Context())
	healthy := true
	problems := make([]string, 0)
	for _, database := range databases {
		if database.Installed && database.Healthy {
			continue
		}
		healthy = false
		problems = append(problems, string(database.Engine)+": "+database.Problem)
	}
	response := gin.H{
		"application": "soar",
		"version":     system.Version,
		"healthy":     healthy,
		"problems":    problems,
		"databases":   databases,
	}
	if metrics, err := system.GetNodeMetrics("/"); err == nil {
		response["metrics"] = metrics
	} else {
		response["metrics_error"] = err.Error()
	}
	c.JSON(http.StatusOK, response)
}

func postSoarUpdate(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
	defer cancel()
	result, err := updater.Update(ctx)
	if err != nil {
		soarError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, result)
	if result.Updated {
		go updater.RestartServiceAfter(1500 * time.Millisecond)
	}
}

// postL7Verify marks a player's address as verified after they solved the
// browser captcha. The Panel forwards either the opaque captcha code issued to
// the player, or an already-resolved server uuid + ip pair.
func postL7Verify(c *gin.Context) {
	mgr := l7.Default()
	if mgr == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "l7 protection is not enabled on this node"})
		return
	}
	var body struct {
		Code string `json:"code"`
		UUID string `json:"uuid"`
		IP   string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid request body"})
		return
	}
	if body.Code != "" {
		if uuid, ok := mgr.VerifyCode(body.Code); ok {
			c.JSON(http.StatusOK, gin.H{"verified": true, "uuid": uuid})
			return
		}
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "unknown or expired verification code"})
		return
	}
	if body.UUID != "" && body.IP != "" {
		if mgr.VerifyAddress(body.UUID, body.IP) {
			c.JSON(http.StatusOK, gin.H{"verified": true, "uuid": body.UUID})
			return
		}
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "no active protection for that server"})
		return
	}
	c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": "a captcha code or uuid/ip pair is required"})
}

// getServerL7Stats returns live L7 protection statistics for a server. With a
// ?port= query parameter a single port snapshot is returned; without it the
// response carries every protected port of the server.
func getServerL7Stats(c *gin.Context) {
	mgr := l7.Default()
	if mgr == nil {
		c.JSON(http.StatusOK, l7.StatsSnapshot{})
		return
	}
	s := middleware.ExtractServer(c)
	if raw := c.Query("port"); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid port"})
			return
		}
		snapshot, ok := mgr.Stats(s.ID(), port)
		if !ok {
			c.JSON(http.StatusOK, l7.StatsSnapshot{Enabled: false, Port: port})
			return
		}
		c.JSON(http.StatusOK, snapshot)
		return
	}
	ports := mgr.StatsAll(s.ID())
	c.JSON(http.StatusOK, gin.H{"enabled": len(ports) > 0, "ports": ports})
}

// getServerL4Stats returns live L4 firewall statistics for a server. With a
// ?port= query parameter a single port snapshot is returned; without it the
// response carries every protected port of the server.
func getServerL4Stats(c *gin.Context) {
	mgr := l4.Default()
	if mgr == nil {
		c.JSON(http.StatusOK, gin.H{"enabled": false, "ports": []l4.StatsSnapshot{}})
		return
	}
	s := middleware.ExtractServer(c)
	if raw := c.Query("port"); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid port"})
			return
		}
		snapshot := mgr.Stats(s.ID(), port)
		if snapshot == nil {
			c.JSON(http.StatusOK, l4.StatsSnapshot{Enabled: false, Port: port})
			return
		}
		c.JSON(http.StatusOK, snapshot)
		return
	}
	ports := mgr.StatsAll(s.ID())
	c.JSON(http.StatusOK, gin.H{"enabled": len(ports) > 0, "ports": ports})
}

func parseDatabaseEngine(c *gin.Context) (databasehost.Engine, bool) {
	engine, err := databasehost.ParseEngine(c.Param("engine"))
	if err != nil {
		soarError(c, err)
		return "", false
	}
	return engine, true
}

func getDatabaseEngines(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"data": databasehost.Default().List(c.Request.Context())})
}

func getDatabaseEngineHealth(c *gin.Context) {
	engine, ok := parseDatabaseEngine(c)
	if !ok {
		return
	}
	status := databasehost.Default().Status(c.Request.Context(), engine)
	code := http.StatusOK
	if !status.Installed {
		code = http.StatusNotFound
	} else if !status.Healthy {
		code = http.StatusServiceUnavailable
	}
	c.JSON(code, status)
}

func postDatabaseEngineInstall(c *gin.Context) {
	engine, ok := parseDatabaseEngine(c)
	if !ok {
		return
	}
	var body struct {
		Update bool `json:"update"`
	}
	_ = c.ShouldBindJSON(&body)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Minute)
	defer cancel()
	status, err := databasehost.Default().Install(ctx, engine, body.Update)
	if err != nil {
		soarError(c, err)
		return
	}
	c.JSON(http.StatusOK, status)
}

func deleteDatabaseEngine(c *gin.Context) {
	engine, ok := parseDatabaseEngine(c)
	if !ok {
		return
	}
	if err := databasehost.Default().Uninstall(c.Request.Context(), engine); err != nil {
		soarError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func postDatabase(c *gin.Context) {
	engine, ok := parseDatabaseEngine(c)
	if !ok {
		return
	}
	var request databasehost.CreateRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		return
	}
	host := c.Request.Host
	if value, _, err := net.SplitHostPort(host); err == nil {
		host = value
	}
	connection, err := databasehost.Default().Create(c.Request.Context(), host, engine, request)
	if err != nil {
		soarError(c, err)
		return
	}
	c.JSON(http.StatusCreated, connection)
}

func deleteDatabase(c *gin.Context) {
	engine, ok := parseDatabaseEngine(c)
	if !ok {
		return
	}
	if err := databasehost.Default().Delete(c.Request.Context(), engine, c.Param("database")); err != nil {
		soarError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func patchDatabasePassword(c *gin.Context) {
	engine, ok := parseDatabaseEngine(c)
	if !ok {
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		return
	}
	if err := databasehost.Default().RotatePassword(c.Request.Context(), engine, c.Param("database"), body.Password); err != nil {
		soarError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
