// Ortelius v11 deppkg Microservice that handles creating and retrieving Dependencies
package main

import (
	"context"
	"encoding/json"

	_ "cli/docs"

	"github.com/arangodb/go-driver"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/swagger"
	"github.com/ortelius/scec-commons/database"
	"github.com/ortelius/scec-commons/model"
)

var logger = database.InitLogger()
var dbconn = database.InitializeDB()

// GetDepPkgs godoc
// @Summary Get a List of DepPkgs
// @Description Get a list of DepPkgs.
// @Tags DepPkgs
// @Accept */*
// @Produce json
// @Success 200
// @Router /msapi/deppkg [get]
func GetDepPkgs(c *fiber.Ctx) error {

	var cursor driver.Cursor       // db cursor for rows
	var err error                  // for error handling
	var ctx = context.Background() // use default database context

	// query all the deppkg in the collection
	aql := `FOR deppkg in evidence
			FILTER (deppkg.objtype == 'deppkg')
			RETURN deppkg`

	// execute the query with no parameters
	if cursor, err = dbconn.Database.Query(ctx, aql, nil); err != nil {
		logger.Sugar().Errorf("Failed to run query: %v", err) // log error
	}

	defer cursor.Close() // close the cursor when returning from this function

	deppkgs := model.NewPackages() // define a list of deppkgs to be returned

	for cursor.HasMore() { // loop thru all of the documents

		deppkg := model.NewPackage() // fetched dependency package
		var meta driver.DocumentMeta // data about the fetch

		// fetch a document from the cursor
		if meta, err = cursor.ReadDocument(ctx, deppkg); err != nil {
			logger.Sugar().Errorf("Failed to read document: %v", err)
		}
		deppkgs.Packages = append(deppkgs.Packages, deppkg)                  // add the Dependency to the list
		logger.Sugar().Infof("Got doc with key '%s' from query\n", meta.Key) // log the key
	}

	return c.JSON(deppkgs) // return the list of dependencies in JSON format
}

// GetDepkkg godoc
// @Summary Get a DepPkg
// @Description Get a deppkg based on the _key or name.
// @Tags deppkg
// @Accept */*
// @Produce json
// @Success 200
// @Router /msapi/deppkg/:key [get]
func GetDepPkg(c *fiber.Ctx) error {

	var cursor driver.Cursor       // db cursor for rows
	var err error                  // for error handling
	var ctx = context.Background() // use default database context

	key := c.Params("key")                // key from URL
	parameters := map[string]interface{}{ // parameters
		"key": key,
	}

	// query the deppkgs that match the key or name
	aql := `FOR deppkg in evidence
			FILTER (deppkg.name == @key or deppkg._key == @key)
			RETURN deppkg`

	// run the query with patameters
	if cursor, err = dbconn.Database.Query(ctx, aql, parameters); err != nil {
		logger.Sugar().Errorf("Failed to run query: %v", err)
	}

	defer cursor.Close() // close the cursor when returning from this function

	deppkg := model.NewPackage() // define a dependency package to be returned

	if cursor.HasMore() { // deppkg found
		var meta driver.DocumentMeta // data about the fetch

		if meta, err = cursor.ReadDocument(ctx, deppkg); err != nil { // fetch the document into the object
			logger.Sugar().Errorf("Failed to read document: %v", err)
		}
		logger.Sugar().Infof("Got doc with key '%s' from query\n", meta.Key)

	} else { // not found so get from NFT Storage
		if jsonStr, exists := database.MakeJSON(key); exists {
			if err := json.Unmarshal([]byte(jsonStr), deppkg); err != nil { // convert the JSON string from LTF into the object
				logger.Sugar().Errorf("Failed to unmarshal from LTS: %v", err)
			}
		}
	}

	return c.JSON(deppkg) // return the deppkg in JSON format
}

// NewDepPkg godoc
// @Summary Create a DepPkg
// @Description Create a new DepPkg and persist it
// @Tags deppkg
// @Accept application/json
// @Produce json
// @Success 200
// @Router /msapi/deppkg [post]
func NewDepPkg(c *fiber.Ctx) error {

	var err error                  // for error handling
	var meta driver.DocumentMeta   // data about the document
	var ctx = context.Background() // use default database context
	deppkg := model.NewPackage()   // define a deppkg to be returned

	if err = c.BodyParser(deppkg); err != nil { // parse the JSON into the deppkg object
		return c.Status(503).Send([]byte(err.Error()))
	}

	cid, dbStr := database.MakeNFT(deppkg) // normalize the object into NFTs and JSON string for db persistence

	logger.Sugar().Infof("%s=%s\n", cid, dbStr) // log the new nft

	// add the deppkg to the database.  Ignore if it already exists since it will be identical
	if meta, err = dbconn.Collection.CreateDocument(ctx, deppkg); err != nil && !driver.IsConflict(err) {
		logger.Sugar().Errorf("Failed to create document: %v", err)
	}
	logger.Sugar().Infof("Created document in collection '%s' in db '%s' key='%s'\n", dbconn.Collection.Name(), dbconn.Database.Name(), meta.Key)

	return c.JSON(deppkg) // return the deppkg object in JSON format.  This includes the new _key
}

// setupRoutes defines maps the routes to the functions
func setupRoutes(app *fiber.App) {

	app.Get("/swagger/*", swagger.HandlerDefault) // handle displaying the swagger
	app.Get("/msapi/deppkg", GetDepPkgs)          // list of deppkgs
	app.Get("/msapi/deppkg/:key", GetDepPkg)      // single deppkg based on name or key
	app.Post("/msapi/deppkg", NewDepPkg)          // save a single deppkg
}

// @title Ortelius v11 DepPkg Microservice
// @version 11.0.0
// @description RestAPI for the deppkg Object
// @description ![Release](https://img.shields.io/github/v/release/ortelius/scec-deppkg?sort=semver)
// @description ![license](https://img.shields.io/github/license/ortelius/scec-deppkg)
// @description
// @description ![Build](https://img.shields.io/github/actions/workflow/status/ortelius/scec-deppkg/build-push-chart.yml)
// @description [![MegaLinter](https://github.com/ortelius/scec-deppkg/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/scec-deppkg/actions?query=workflow%3AMegaLinter+branch%3Amain)
// @description ![CodeQL](https://github.com/ortelius/scec-deppkg/workflows/CodeQL/badge.svg)
// @description [![OpenSSF-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/scec-deppkg/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/scec-deppkg)
// @description
// @description ![Discord](https://img.shields.io/discord/722468819091849316)

// @termsOfService http://swagger.io/terms/
// @contact.name Ortelius Google Group
// @contact.email ortelius-dev@googlegroups.com
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:3000
// @BasePath /msapi/deppkg
func main() {
	port := ":" + database.GetEnvDefault("MS_PORT", "8080") // database port
	app := fiber.New()                                      // create a new fiber application
	app.Use(cors.New(cors.Config{
		AllowHeaders: "Origin, Content-Type, Accept",
		AllowOrigins: "*",
	}))

	setupRoutes(app) // define the routes for this microservice

	if err := app.Listen(port); err != nil { // start listening for incoming connections
		logger.Sugar().Fatalf("Failed get the microservice running: %v", err)
	}
}
