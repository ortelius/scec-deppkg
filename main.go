// Ortelius v11 package Microservice that handles creating and retrieving Dependencies
package main

import (
	"context"
	"encoding/json"

	_ "cli/docs"

	driver "github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/swagger"
	"github.com/ortelius/scec-commons/database"
	"github.com/ortelius/scec-commons/model"
)

var logger = database.InitLogger()
var dbconn = database.InitializeDB("sbom")

// GetPackages godoc
// @Summary Get a List of Packages
// @Description Get a list of Packages.
// @Tags Packages
// @Accept */*
// @Produce json
// @Success 200
// @Router /msapi/package [get]
func GetPackages(c *fiber.Ctx) error {

	var cursor driver.Cursor       // db cursor for rows
	var err error                  // for error handling
	var ctx = context.Background() // use default database context

	// query all the package in the collection
	aql := `FOR sbom in sbom
			FILTER (sbom.objtype == 'SBOM')
			RETURN sbom`

	// execute the query with no parameters
	if cursor, err = dbconn.Database.Query(ctx, aql, nil); err != nil {
		logger.Sugar().Errorf("Failed to run query: %v", err) // log error
	}

	defer cursor.Close() // close the cursor when returning from this function

	var packages []*model.Package // define a list of packages to be returned

	for cursor.HasMore() { // loop thru all of the documents

		pkg := model.NewPackage()    // fetched dependency package
		var meta driver.DocumentMeta // data about the fetch

		// fetch a document from the cursor
		if meta, err = cursor.ReadDocument(ctx, pkg); err != nil {
			logger.Sugar().Errorf("Failed to read document: %v", err)
		}
		packages = append(packages, pkg)                                     // add the Dependency to the list
		logger.Sugar().Infof("Got doc with key '%s' from query\n", meta.Key) // log the key
	}

	return c.JSON(packages) // return the list of dependencies in JSON format
}

// GetPackage godoc
// @Summary Get a Package
// @Description Get a package based on the _key or name.
// @Tags package
// @Accept */*
// @Produce json
// @Success 200
// @Router /msapi/package/:key [get]
func GetPackage(c *fiber.Ctx) error {

	var cursor driver.Cursor       // db cursor for rows
	var err error                  // for error handling
	var ctx = context.Background() // use default database context

	key := c.Params("key")                // key from URL
	parameters := map[string]interface{}{ // parameters
		"key": key,
	}

	// query the packages that match the key or name
	aql := `FOR sbom in sbom
			FILTER sbom._key == @key
			RETURN sbom`

	// run the query with patameters
	if cursor, err = dbconn.Database.Query(ctx, aql, &driver.QueryOptions{BindVars: parameters}); err != nil {
		logger.Sugar().Errorf("Failed to run query: %v", err)
	}

	defer cursor.Close() // close the cursor when returning from this function

	pkg := model.NewPackage() // define a dependency package to be returned

	if cursor.HasMore() { // package found
		var meta driver.DocumentMeta // data about the fetch

		if meta, err = cursor.ReadDocument(ctx, pkg); err != nil { // fetch the document into the object
			logger.Sugar().Errorf("Failed to read document: %v", err)
		}
		logger.Sugar().Infof("Got doc with key '%s' from query\n", meta.Key)

	} else { // not found so get from NFT Storage
		if jsonStr, exists := database.MakeJSON(key); exists {
			if err := json.Unmarshal([]byte(jsonStr), pkg); err != nil { // convert the JSON string from LTF into the object
				logger.Sugar().Errorf("Failed to unmarshal from LTS: %v", err)
			}
		}
	}

	return c.JSON(pkg) // return the package in JSON format
}

// NewSBOM godoc
// @Summary Upload an SBOM
// @Description Create a new SBOM and persist it
// @Tags sbom
// @Accept application/json
// @Produce json
// @Success 200
// @Router /msapi/sbom [post]
func NewSBOM(c *fiber.Ctx) error {

	var err error                  // for error handling
	var meta driver.DocumentMeta   // data about the document
	var ctx = context.Background() // use default database context
	sbom := model.NewSBOM()        // define a package to be returned

	if err = c.BodyParser(sbom); err != nil { // parse the JSON into the package object
		return c.Status(503).Send([]byte(err.Error()))
	}

	cid, dbStr := database.MakeNFT(sbom) // normalize the object into NFTs and JSON string for db persistence

	logger.Sugar().Infof("%s=%s\n", cid, dbStr) // log the new nft

	// add the package to the database.  Ignore if it already exists since it will be identical
	var resp driver.CollectionDocumentCreateResponse

	if resp, err = dbconn.Collection.CreateDocument(ctx, sbom); err != nil && !shared.IsConflict(err) {
		logger.Sugar().Errorf("Failed to create document: %v", err)
	}
	meta = resp.DocumentMeta
	logger.Sugar().Infof("Created document in collection '%s' in db '%s' key='%s'\n", dbconn.Collection.Name(), dbconn.Database.Name(), meta.Key)

	var res model.ResponseKey
	res.Key = sbom.Key
	return c.JSON(res) // return the package object in JSON format.  This includes the new _key
}

// setupRoutes defines maps the routes to the functions
func setupRoutes(app *fiber.App) {

	app.Get("/swagger/*", swagger.HandlerDefault) // handle displaying the swagger
	app.Get("/msapi/package", GetPackages)        // list of packages
	app.Get("/msapi/package/:key", GetPackage)    // single package based on name or key
	app.Post("/msapi/sbom", NewSBOM)              // save a single package
}

// @title Ortelius v11 Package Microservice
// @version 11.0.0
// @description RestAPI for the package Object
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
// @BasePath /msapi/package
func main() {
	port := ":" + database.GetEnvDefault("MS_PORT", "8081") // database port
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
