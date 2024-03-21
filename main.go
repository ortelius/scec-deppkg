// Ortelius v11 package Microservice that handles creating and retrieving Dependencies
package main

import (
	"context"
	"net/http"
	"sort"
	"strings"

	_ "cli/docs"
	"cli/models"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
	"github.com/goark/go-cvss/v2/metric"
	metric_v3 "github.com/goark/go-cvss/v3/metric"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/swagger"
	"github.com/ortelius/scec-commons/database"
	"github.com/ortelius/scec-commons/model"
	"github.com/pkg/errors"
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

	var cursor arangodb.Cursor     // db cursor for rows
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

		pkg := model.NewPackage()      // fetched dependency package
		var meta arangodb.DocumentMeta // data about the fetch

		// fetch a document from the cursor
		if meta, err = cursor.ReadDocument(ctx, pkg); err != nil {
			logger.Sugar().Errorf("Failed to read document: %v", err)
		}
		packages = append(packages, pkg)                                   // add the Dependency to the list
		logger.Sugar().Infof("Got doc with key '%s' from query", meta.Key) // log the key
	}

	return c.JSON(packages) // return the list of dependencies in JSON format
}

// GetPackages4SBOM godoc
// @Summary Get a Package
// @Description Get a package based on the _key or name.
// @Tags package
// @Accept */*
// @Produce json
// @Success 200
// @Router /msapi/package/:key [get]
func GetPackages4SBOM(c *fiber.Ctx) error {

	compid := c.Query("compid")
	keys := strings.Split(c.Query("appid"), ",")
	deptype := c.Query("deptype")

	if compid != "" {
		keys = append(keys, compid)
	}

	if deptype == "license" {
		data := map[string]interface{}{
			"data": GetLicenses(keys),
		}
		return c.JSON(data)
	}

	data := map[string]interface{}{
		"data": GetCVEs(keys),
	}
	return c.JSON(data)
}

// GetLicenses will return a list of packages and corresponding licenses
func GetLicenses(keys []string) []*model.PackageLicense {
	var cursor arangodb.Cursor            // db cursor for rows
	var err error                         // for error handling
	var ctx = context.Background()        // use default database context
	packages := []*model.PackageLicense{} // list of packages in the SBOM

	for _, key := range keys {

		if key == "" {
			continue
		}

		parameters := map[string]interface{}{ // parameters
			"key": key,
		}

		// query the packages that match the key or name
		aql := `FOR sbom IN sbom
			FILTER sbom.objtype == "SBOM" && sbom._key == @key
			FOR packages IN sbom.content.components
				LET lics = LENGTH(packages.licenses) > 0
				? (FOR lic IN packages.licenses
					FILTER LENGTH(packages.licenses) > 0
						LET id = LENGTH(lic.license.id) > 0
						? lic.license.id
						: SPLIT(lic.license.name, "----")[0]
						RETURN id
					)
				: [""]

				FOR lic IN lics
					RETURN {
					"key": sbom._key,
					"packagename": packages.name,
					"packageversion": packages.version,
					"url": packages.purl,
					"name": lic,
					"pkgtype": SPLIT(SPLIT(packages.purl, ":")[1], "/")[0]
					}`

		// run the query with patameters
		if cursor, err = dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters}); err != nil {
			logger.Sugar().Errorf("Failed to run query: %v", err)
		}

		defer cursor.Close() // close the cursor when returning from this function

		for cursor.HasMore() { // loop thru all of the documents

			pkg := model.NewPackageLicense() // define a dependency package to be returned

			if _, err = cursor.ReadDocument(ctx, pkg); err != nil { // fetch the document into the object
				logger.Sugar().Errorf("Failed to read document: %v", err)
			}

			url := "https://spdx.org/licenses/" + pkg.License + ".html"

			resp, err := http.Head(url)
			if err == nil {
				if resp.StatusCode == http.StatusOK {
					pkg.URL = url
				}
			}

			if resp != nil {
				resp.Body.Close()
			}

			packages = append(packages, pkg)
		}
	}
	return packages
}

// GetCVEs will return a list of packages that have CVEs
func GetCVEs(keys []string) ([]*model.PackageCVE, error) {
	var cursor arangodb.Cursor
	var purlCursor arangodb.Cursor
	var err error
	var ctx = context.Background()
	packages := []*model.PackageCVE{}

	for _, key := range keys {
		if key == "" {
			continue
		}

		parameters := map[string]interface{}{
			"key": key,
		}

		aql := `FOR sbom IN sbom
				FILTER sbom.objtype == "SBOM" && sbom._key == @key
				FOR packages IN sbom.content.components
					LET purl = packages.purl != null ? packages.purl : CONCAT("pkg:swid/", packages.swid.name, "@", packages.swid.version, "?tag_id=", packages.swid.tagId)

					RETURN {
						"key": sbom._key,
						"packagename": packages.name,
						"packageversion": packages.version,
						"url": purl,
						"cve": "",
						"pkgtype": SPLIT(SPLIT(packages.purl, ":")[1], "/")[0]
						}`

		if purlCursor, err = dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters}); err != nil {
			logger.Sugar().Errorf("Failed to run purlCursor query: %v", err)
			return nil, errors.Wrap(err, "failed to run purlCursor query")
		}
		defer purlCursor.Close()

		for purlCursor.HasMore() {
			cvelist := make(map[string]bool)
			pkg := model.NewPackageCVE()

			if _, err = purlCursor.ReadDocument(ctx, &pkg); err != nil {
				logger.Sugar().Errorf("Failed to read purlCursor document: %v", err)
				return nil, errors.Wrap(err, "failed to read purlCursor document")
			}

			purl := pkg.URL
			pkgInfo, _ := models.PURLToPackage(purl)
			osvPkg := models.PackageDetails{
				Name:      pkgInfo.Name,
				Version:   pkgInfo.Version,
				Commit:    pkgInfo.Commit,
				Ecosystem: models.Ecosystem(pkgInfo.Ecosystem),
				CompareAs: models.Ecosystem(pkgInfo.Ecosystem),
			}

			parameters = map[string]interface{}{
				"name": pkgInfo.Name,
			}

			aql = `FOR vuln IN vulns
					FOR affected in vuln.affected
						FILTER (@name in vuln.affected[*].package.name AND affected.package.name == @name)
						RETURN merge({ID: vuln._key}, vuln)`

			if len(strings.TrimSpace(purl)) > 0 {
				parts := strings.Split(purl, "@")
				parts = strings.Split(parts[0], "?")
				purl := parts[0]

				parameters = map[string]interface{}{
					"name": pkgInfo.Name,
					"purl": purl,
				}

				aql = `FOR vuln IN vulns
						FOR affected in vuln.affected
							FILTER (@name in vuln.affected[*].package.name AND affected.package.name == @name) OR
								(@purl in vuln.affected[*].package.purl AND STARTS_WITH(affected.package.purl,@purl))
							RETURN merge({ID: vuln._key}, vuln)`
			}

			if cursor, err = dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters}); err != nil {
				logger.Sugar().Errorf("Failed to run cursor query: %v", err)
				return nil, errors.Wrap(err, "failed to run cursor query")
			}

			score := 0.0
			severity := ""
			defer cursor.Close()

			for cursor.HasMore() {
				var vuln models.Vulnerability

				if _, err = cursor.ReadDocument(ctx, &vuln); err != nil {
					logger.Sugar().Errorf("Failed to read cursor document: %v", err)
					return nil, errors.Wrap(err, "failed to read cursor document")
				}

				if models.IsAffected(vuln, osvPkg) && !cvelist[vuln.ID] {
					cvepkg := model.NewPackageCVE()

					cvelist[vuln.ID] = true
					cvepkg.Key = pkg.Key
					cvepkg.Language = pkg.Language
					cvepkg.Name = pkg.Name
					cvepkg.URL = pkg.URL
					cvepkg.Version = pkg.Version
					cvepkg.CVE = vuln.ID
					cvepkg.Summary = vuln.Summary

					if len(vuln.Severity) > 0 {
						if vuln.Severity[0].Type == "CVSS_V3" {
							if bm, err := metric_v3.NewBase().Decode(vuln.Severity[0].Score); err == nil {
								if bm.Score() > score {
									score = bm.Score()
									severity = bm.Severity().String()
								}
							}
						} else {
							if bm, err := metric.NewBase().Decode(vuln.Severity[0].Score); err == nil {
								if bm.Score() > score {
									score = bm.Score()
									severity = bm.Severity().String()
								}
							}
						}
					}
					cvepkg.Score = score
					cvepkg.Severity = severity

					if severity == "" {
						cvepkg.Severity = "None"
					}

					if cvepkg.CVE != "" {
						packages = append(packages, cvepkg)
					}
				}
			}
		}
	}

	sort.Slice(packages, func(i, j int) bool {
		a, b := packages[i], packages[j]
		return a.Score > b.Score || (a.Score == b.Score && (a.Name < b.Name || (a.Name == b.Name && a.Version < b.Version)))
	})

	return packages, nil
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
	var ctx = context.Background() // use default database context
	sbom := model.NewSBOM()        // define a package to be returned

	if err = c.BodyParser(sbom); err != nil { // parse the JSON into the package object
		return c.Status(503).Send([]byte(err.Error()))
	}

	// for backward compatibility skip creating a NFT if the compid is part of the POST
	// this will enable mapping of the sbom to the compid in the postgresdb
	if sbom.Key == "" {
		cid, dbStr := database.MakeNFT(sbom)        // normalize the object into NFTs and JSON string for db persistence
		logger.Sugar().Infof("%s=%s\n", cid, dbStr) // log the new nft
	}

	// add the package to the database.  Replace if it already exists
	overwrite := true
	options := &arangodb.CollectionDocumentCreateOptions{
		Overwrite: &overwrite,
	}

	// update existing docs and add if missing
	if _, err = dbconn.Collection.CreateDocumentWithOptions(ctx, sbom, options); err != nil {
		logger.Sugar().Errorf("Failed to create document: %v", err)
	}

	logger.Sugar().Infof("Created document in collection '%s' in db '%s' key='%s'\n", dbconn.Collection.Name(), dbconn.Database.Name(), sbom.Key)

	var res model.ResponseKey
	res.Key = sbom.Key
	return c.JSON(res) // return the package object in JSON format.  This includes the new _key
}

// NewProvenance godoc
// @Summary Upload Provenance JSON
// @Description Create a new Provenance and persist it
// @Tags provenance
// @Accept application/json
// @Produce json
// @Success 200
// @Router /msapi/provenance [post]
func NewProvenance(c *fiber.Ctx) error {

	var err error                       // for error handling
	var meta arangodb.DocumentMeta      // data about the document
	var ctx = context.Background()      // use default database context
	provenance := model.NewProvenance() // define a package to be returned

	if err = c.BodyParser(provenance); err != nil { // parse the JSON into the package object
		return c.Status(503).Send([]byte(err.Error()))
	}

	cid, dbStr := database.MakeNFT(provenance) // normalize the object into NFTs and JSON string for db persistence

	logger.Sugar().Infof("%s=%s\n", cid, dbStr) // log the new nft

	// add the package to the database.  Ignore if it already exists since it will be identical
	var resp arangodb.CollectionDocumentCreateResponse

	if resp, err = dbconn.Collection.CreateDocument(ctx, provenance); err != nil && !shared.IsConflict(err) {
		logger.Sugar().Errorf("Failed to create document: %v", err)
	}
	meta = resp.DocumentMeta
	logger.Sugar().Infof("Created document in collection '%s' in db '%s' key='%s'\n", dbconn.Collection.Name(), dbconn.Database.Name(), meta.Key)

	var res model.ResponseKey
	res.Key = provenance.Key
	return c.JSON(res) // return the package object in JSON format.  This includes the new _key
}

// SBOMType returns full_file to signify that a complete SBOM is supported
func SBOMType(c *fiber.Ctx) error {
	// Return a JSON response with SBOMType: 'full_file'
	response := fiber.Map{"SBOMType": "fullfile"}
	return c.JSON(response)
}

// HealthCheck for kubernetes to determine if it is in a good state
func HealthCheck(c *fiber.Ctx) error {
	return c.SendString("OK")
}

// setupRoutes defines maps the routes to the functions
func setupRoutes(app *fiber.App) {

	app.Get("/swagger/*", swagger.HandlerDefault) // handle displaying the swagger
	app.Get("/msapi/packages", GetPackages)       // list of packages
	app.Get("/msapi/package", GetPackages4SBOM)   // single package based on name or key
	app.Get("/msapi/sbomtype", SBOMType)          // tell client that this microservice supports a full SBOM on the SBOM Post
	app.Post("/msapi/package", NewSBOM)           // save a single package
	app.Post("/msapi/provenance", NewProvenance)  // save a single package
	app.Get("/health", HealthCheck)               // kubernetes health check
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
	app := fiber.New()
	app.Use(compress.New())
	// create a new fiber application
	app.Use(cors.New(cors.Config{
		AllowHeaders: "Origin, Content-Type, Accept",
		AllowOrigins: "*",
	}))

	setupRoutes(app) // define the routes for this microservice

	if err := app.Listen(port); err != nil { // start listening for incoming connections
		logger.Sugar().Fatalf("Failed get the microservice running: %v", err)
	}
}
