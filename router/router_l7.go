package router

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pterodactyl/wings/router/middleware"
)

// getServerL7Status returns the current L7 proxy state for a server.
func getServerL7Status(c *gin.Context) {
	s := ExtractServer(c)
	cfg := s.Config()
	c.JSON(http.StatusOK, gin.H{
		"enabled": cfg.Allocations.L7Filter,
		"port":    cfg.Allocations.DefaultMapping.Port,
	})
}

// postServerL7Enable enables L7 protection on the server's primary port.
func postServerL7Enable(c *gin.Context) {
	s := ExtractServer(c)

	cfg := s.Config()
	if cfg.Allocations.L7Filter {
		c.JSON(http.StatusOK, gin.H{"enabled": true, "message": "L7 already enabled"})
		return
	}

	if err := s.StartL7Proxy(); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"enabled": true})
}

// postServerL7Disable disables L7 protection on the server's primary port.
func postServerL7Disable(c *gin.Context) {
	s := ExtractServer(c)

	if err := s.StopL7Proxy(); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"enabled": false})
}
