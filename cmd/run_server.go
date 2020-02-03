package cmd

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/RichardKnop/go-oauth2-server/services"
	"github.com/gorilla/mux"
	"github.com/phyber/negroni-gzip/gzip"
	"github.com/urfave/negroni"
	"gopkg.in/tylerb/graceful.v1"
)

// RunServer runs the app
func RunServer(configBackend string) error {
	cnf, db, redisClient, err := initConfigDB(true, true, configBackend)
	if err != nil {
		return err
	}
	defer db.Close()

	// start the services
	if err := services.Init(cnf, db, redisClient); err != nil {
		return err
	}
	defer services.Close()

	// Start a classic negroni app
	app := negroni.New()
	app.Use(negroni.NewRecovery())
	app.Use(negroni.NewLogger())
	app.Use(gzip.Gzip(gzip.DefaultCompression))
	app.Use(negroni.NewStatic(http.Dir("public")))

	// Create a router instance
	router := mux.NewRouter()

	// Add routes
	services.HealthService.RegisterRoutes(router, "/v1")
	services.OauthService.RegisterRoutes(router, "/v1/oauth")
	// 暂时禁止web上的操作
	//services.WebService.RegisterRoutes(router, "/web")

	// Set the router
	app.UseHandler(router)

	port := strconv.Itoa(cnf.Port)
	addr := ":" + port
	fmt.Println(addr)
	// Run the server on port 8080, gracefully stop on SIGTERM signal
	graceful.Run(addr, 5*time.Second, app)

	return nil
}
