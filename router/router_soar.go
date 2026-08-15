package router

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/pterodactyl/wings/databasehost"
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
	c.JSON(http.StatusOK, gin.H{
		"application": "soar",
		"version":     system.Version,
		"databases":   databasehost.Default().List(c.Request.Context()),
	})
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
