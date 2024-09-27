// Ortelius v11 package Microservice that handles creating and retrieving Dependencies
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"

	_ "github.com/ortelius/scec-deppkg/docs"
	"github.com/ortelius/scec-deppkg/models"

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
var dbconn = database.InitializeDatabase()
var licensesMap = make(map[string]License)

// License represents the structure of each license in the JSON data
type License struct {
	Reference       string   `json:"reference"`
	IsDeprecated    bool     `json:"isDeprecatedLicenseId"`
	DetailsURL      string   `json:"detailsUrl"`
	ReferenceNumber int      `json:"referenceNumber"`
	Name            string   `json:"name"`
	LicenseID       string   `json:"licenseId"`
	SeeAlso         []string `json:"seeAlso"`
	IsOsiApproved   bool     `json:"isOsiApproved"`
}

// Licenses represents the structure of the JSON data
type Licenses struct {
	Licenses []License `json:"licenses"`
}

// fetchAndParseLicenses fetches the JSON data from the URL and parses it into a map
func fetchAndParseLicenses(licensesMap map[string]License) {

	// Fetch the JSON data from the URL
	url := "https://github.com/spdx/license-list-data/raw/main/json/licenses.json"

	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	// Unmarshal the JSON data into a Licenses struct
	var licensesData Licenses
	if err := json.Unmarshal(body, &licensesData); err != nil {
		return
	}

	// Create a map from the Licenses struct

	for _, license := range licensesData.Licenses {
		licensesMap[license.LicenseID] = license
	}
}

// getLicenseURL checks if the given license ID exists in the map
func getLicenseURL(licensesMap map[string]License, licenseID string) string {
	if lic, exists := licensesMap[licenseID]; exists {
		return lic.Reference
	}

	return ""
}

// GetPackages godoc
// @Summary Get a List of Packages that are like the passed package name and version
// @Description Get a list of Packages.
// @Tags Packages
// @Accept */*
// @Produce json
// @Success 200
// @Router /msapi/package [get]
func GetPackages(c *fiber.Ctx) error {

	var cursor arangodb.Cursor            // db cursor for rows
	var err error                         // for error handling
	var ctx = context.Background()        // use default database context
	packages := []*model.PackageLicense{} // list of packages in the SBOM

	pkgname := "%" + c.Query("pkgname") + "%"
	pkgversion := "%" + c.Query("pkgversion") + "%"

	parameters := map[string]interface{}{
		"pkgname": pkgname,
	}

	// query all the package in the collection
	aql := `FOR sbom IN sbom
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

				LET pkgType = SPLIT(SPLIT(packages.purl, ":")[1], "/")[0]

				FOR lic IN lics
				    FILTER packages.name LIKE @pkgname
					RETURN {
					"key": sbom._key,
					"packagename": packages.name,
					"packageversion": packages.version,
					"purl": packages.purl,
					"name": lic,
					"pkgtype": pkgType
					}`

	if pkgversion != "" {
		aql = `FOR sbom IN sbom
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

			LET pkgType = SPLIT(SPLIT(packages.purl, ":")[1], "/")[0]

			FOR lic IN lics
				FILTER packages.name LIKE @pkgname and packages.version LIKE @pkgversion
				RETURN {
				"key": sbom._key,
				"packagename": packages.name,
				"packageversion": packages.version,
				"purl": packages.purl,
				"name": lic,
				"pkgtype": pkgType
				}`

		parameters = map[string]interface{}{
			"pkgname":    pkgname,
			"pkgversion": pkgversion,
		}
	}

	// execute the query with no parameters
	if cursor, err = dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters}); err != nil {
		logger.Sugar().Errorf("Failed to run query: %v", err) // log error
	}

	defer cursor.Close() // close the cursor when returning from this function

	for cursor.HasMore() { // loop thru all of the documents

		pkg := model.NewPackageLicense() // define a dependency package to be returned

		if _, err = cursor.ReadDocument(ctx, pkg); err != nil { // fetch the document into the object
			logger.Sugar().Errorf("Failed to read document: %v", err)
		}

		pkg.URL = getLicenseURL(licensesMap, pkg.License)

		packages = append(packages, pkg)

	}
	data := map[string]interface{}{
		"data": packages,
	}
	return c.JSON(data)
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
	appid := c.Query("appid")

	keys := strings.Split(appid, ",")
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

	cvedata, err := GetCVEs(keys)

	if err != nil {
		logger.Sugar().Errorf("GetCVEs returned %v", err)
	}

	data := map[string]interface{}{
		"data": cvedata,
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

		compid := key
		key = strings.ReplaceAll(key, "ap", "")
		key = strings.ReplaceAll(key, "av", "")
		key = strings.ReplaceAll(key, "co", "")
		key = strings.ReplaceAll(key, "cv", "")

		parameters := map[string]interface{}{ // parameters
			"key": key,
		}

		// query the packages that match the key or name
		aql := `FOR sbom IN sbom
			FILTER sbom._key == @key OR sbom.cid == @key
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

				LET pkgType = SPLIT(SPLIT(packages.purl, ":")[1], "/")[0]

				FOR lic IN lics
					RETURN {
					"key": sbom._key,
					"packagename": packages.name,
					"packageversion": packages.version,
					"purl": packages.purl,
					"name": lic,
					"pkgtype": pkgType
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

			pkg.CompID = compid
			pkg.URL = getLicenseURL(licensesMap, pkg.License)

			packages = append(packages, pkg)

		}
	}
	return packages
}

// Purl2Comp will read the purls in the SBOM and create corresponding comps
func Purl2Comp(dhurl string, cookies []*http.Cookie, key string) {
	var purlCursor arangodb.Cursor // db cursor for rows
	var err error                  // for error handling
	var ctx = context.Background() // use default database context

	parameters := map[string]interface{}{ // parameters
		"key": key,
	}

	aql := `FOR sbom IN sbom
			FILTER sbom._key == @key OR sbom.cid == @key
			FOR packages IN sbom.content.components
				LET purl = packages.purl != null ? packages.purl : CONCAT("pkg:swid/", packages.swid.name, "@", packages.swid.version, "?tag_id=", packages.swid.tagId)

				RETURN {
					"key": sbom._key,
					"packagename": packages.name,
					"packageversion": packages.version,
					"purl": purl,
					"cve": "",
					"pkgtype": SPLIT(SPLIT(packages.purl, ":")[1], "/")[0]
					}`

	// run the query with patameters
	if purlCursor, err = dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters}); err != nil {
		logger.Sugar().Errorf("Failed to run purlCursor query: %v", err)
	}

	defer purlCursor.Close() // close the cursor when returning from this function

	for purlCursor.HasMore() { // list of purls
		pkg := model.NewPackageCVE()

		if _, err = purlCursor.ReadDocument(ctx, &pkg); err != nil {
			logger.Sugar().Errorf("Failed to read purlCursor document: %v", err)
		}

		type PurlPayload struct {
			Purl string `json:"purl"`
		}

		purl := PurlPayload{Purl: pkg.Purl}

		// Marshal the JSON data into a byte array
		jsonData, err := json.Marshal(purl)
		if err != nil {
			logger.Sugar().Infof("Error marshaling JSON: %v", err)
			return
		}

		// Create a new HTTP request
		req, err := http.NewRequest("POST", dhurl+"/msapi/purl2comp", bytes.NewBuffer(jsonData))
		if err != nil {
			logger.Sugar().Infoln("Error creating request:", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")

		// Forward cookies from the incoming request
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}

		// Send the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			logger.Sugar().Infoln("Error sending request:", err)
			return
		}
		defer resp.Body.Close()
	}
}

// GetCVEs will return a list of packages that have CVEs
func GetCVEs(keys []string) ([]*model.PackageCVE, error) {
	var cursor arangodb.Cursor        // db cursor for rows
	var purlCursor arangodb.Cursor    // db cursor for rows
	var err error                     // for error handling
	var ctx = context.Background()    // use default database context
	packages := []*model.PackageCVE{} // list of packages in the SBOM

	for _, key := range keys {

		if key == "" {
			continue
		}

		compid := key
		key = strings.ReplaceAll(key, "ap", "")
		key = strings.ReplaceAll(key, "av", "")
		key = strings.ReplaceAll(key, "co", "")
		key = strings.ReplaceAll(key, "cv", "")

		parameters := map[string]interface{}{ // parameters
			"key": key,
		}

		aql := `FOR sbom IN sbom
				FILTER sbom._key == @key OR sbom.cid == @key
				FOR packages IN sbom.content.components
					LET purl = packages.purl != null ? packages.purl : CONCAT("pkg:swid/", packages.swid.name, "@", packages.swid.version, "?tag_id=", packages.swid.tagId)

					RETURN {
						"key": sbom._key,
						"packagename": packages.name,
						"packageversion": packages.version,
						"purl": purl,
						"cve": "",
						"pkgtype": SPLIT(SPLIT(packages.purl, ":")[1], "/")[0]
						}`

		// run the query with patameters
		if purlCursor, err = dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters}); err != nil {
			logger.Sugar().Errorf("Failed to run purlCursor query: %v", err)
			return nil, errors.Wrap(err, "failed to run purlCursor query")
		}

		defer purlCursor.Close() // close the cursor when returning from this function

		for purlCursor.HasMore() { // list of purls
			cvelist := make(map[string]bool)

			pkg := model.NewPackageCVE()

			if _, err = purlCursor.ReadDocument(ctx, &pkg); err != nil {
				logger.Sugar().Errorf("Failed to read purlCursor document: %v", err)
				return nil, errors.Wrap(err, "failed to read purlCursor document")
			}

			purl := pkg.Purl
			pkg.CompID = compid

			pkgInfo, _ := models.PURLToPackage(purl)

			osvPkg := models.PackageDetails{
				Name:      pkgInfo.Name,
				Version:   pkgInfo.Version,
				Commit:    pkgInfo.Commit,
				Ecosystem: models.Ecosystem(pkgInfo.Ecosystem),
				CompareAs: models.Ecosystem(pkgInfo.Ecosystem),
			}

			parameters = map[string]interface{}{ // parameters
				"name": pkgInfo.Name,
			}

			aql = `FOR vuln IN vulns
						FILTER @name in (vuln.affected[*].package.name)
						RETURN DISTINCT merge({ID: vuln._key}, vuln)`

			if len(strings.TrimSpace(purl)) > 0 {
				// Split the purl string by "@" and "?"
				parts := strings.Split(purl, "@")
				parts = strings.Split(parts[0], "?")

				// The first part before "@" and "?" is in parts[0]
				purl := parts[0]

				parameters = map[string]interface{}{ // parameters
					"purl": purl,
				}

				aql = `LET purlDoc = (
							FOR p IN purls
							FILTER p.purl == @purl
							RETURN p
						)
						FILTER LENGTH(purlDoc) > 0

						FOR vuln, edge, path IN 1..1 OUTBOUND purlDoc[0]._id GRAPH 'vulnGraph'
							RETURN DISTINCT merge({ID: vuln._key}, vuln)`

			}

			// run the query with patameters
			if cursor, err = dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters}); err != nil {
				logger.Sugar().Errorf("Failed to run cursor query: %v", err)
				return nil, errors.Wrap(err, "failed to run cursor query")
			}

			score := 0.0
			severity := ""
			defer cursor.Close() // close the cursor when returning from this function

			for cursor.HasMore() { // vuln found

				var vuln models.Vulnerability

				if _, err = cursor.ReadDocument(ctx, &vuln); err != nil {
					logger.Sugar().Errorf("Failed to read cursor document: %v", err)
					return nil, errors.Wrap(err, "failed to read cursor document")
				}

				if !cvelist[vuln.ID] && models.IsAffected(vuln, osvPkg) {
					cvepkg := model.NewPackageCVE()

					cvelist[vuln.ID] = true

					cvepkg.Key = pkg.Key
					cvepkg.CompID = pkg.CompID
					cvepkg.Language = pkg.Language
					cvepkg.Name = pkg.Name
					cvepkg.URL = pkg.URL
					cvepkg.Purl = pkg.Purl
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

	key := sbom.Key // save the key from the postgresdb if passed in json data

	// for backward compatibility skip creating a NFT if the compid is part of the POST
	// this will enable mapping of the sbom to the compid in the postgresdb

	cid, dbStr := database.MakeNFT(sbom) // normalize the object into NFTs and JSON string for db persistence

	logger.Sugar().Infof("%s=%s\n", cid, dbStr) // log the new nft
	sbom.Cid = cid

	if key != "" {
		sbom.Key = key
	}

	if sbom.Key == "" {
		return c.Status(503).Send([]byte("Key not defined"))
	}

	if sbom.Content == nil {
		return c.Status(503).Send([]byte("No SBOM Found"))
	}

	// add the package to the database.  Replace if it already exists
	overwrite := true
	options := &arangodb.CollectionDocumentCreateOptions{
		Overwrite: &overwrite,
	}

	// update existing docs and add if missing
	if _, err = dbconn.Collections["sbom"].CreateDocumentWithOptions(ctx, sbom, options); err != nil {
		logger.Sugar().Errorf("Failed to create document: %v", err)
	}

	logger.Sugar().Infof("Created document in collection '%s' in db '%s' key='%s'\n", dbconn.Collections["sbom"].Name(), dbconn.Database.Name(), sbom.Key)

	dhurl := c.BaseURL()

	dhurl = strings.Replace(dhurl, "http:", "https:", 1)

	// Send an HTTP HEAD request to check the redirect
	//nolint:gosec
	resp, err := http.Head(dhurl)
	if err != nil {
		logger.Sugar().Infoln("No https available:", err)
		dhurl = c.BaseURL()
	} else {
		defer resp.Body.Close()

		// Check if the response is a redirect
		if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			dhurl = resp.Header.Get("Location")
		} else if resp.StatusCode != 200 {
			dhurl = c.BaseURL()
		}
	}

	// dhurl := "http://localhost:5003"
	dhurl = strings.Trim(dhurl, "/")
	logger.Sugar().Infof("dhurl=%s", dhurl)

	var cookies []*http.Cookie

	/* 	var resp2 *http.Response
	   	resp2, err = http.Get("http://localhost:8181/dmadminweb/API/login?user=admin&pass=admin")

	   	if err == nil {
	   		cookies = resp2.Cookies()
	   		resp2.Body.Close()
	   	} */

	// Visit all cookies in the request header
	c.Request().Header.VisitAllCookie(func(key, value []byte) {
		// Create a new http.Cookie and add it to the cookies array
		cookie := &http.Cookie{
			Name:  string(key),
			Value: string(value),
		}
		cookies = append(cookies, cookie)
	})

	Purl2Comp(dhurl, cookies, sbom.Key)

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

	if resp, err = dbconn.Collections["provenance"].CreateDocument(ctx, provenance); err != nil && !shared.IsConflict(err) {
		logger.Sugar().Errorf("Failed to create document: %v", err)
	}
	meta = resp.DocumentMeta
	logger.Sugar().Infof("Created document in collection '%s' in db '%s' key='%s'\n", dbconn.Collections["provenance"].Name(), dbconn.Database.Name(), meta.Key)

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
	app.Get("/msapi/package", GetPackages4SBOM)   // get all the packages in an sbom based on a key
	app.Get("/msapi/sbomtype", SBOMType)          // tell client that this microservice supports a full SBOM on the SBOM Post
	app.Post("/msapi/package", NewSBOM)           // save a sbom, if compid is defined then add to comp2sbom graph
	app.Post("/msapi/provenance", NewProvenance)  // save a single package
	app.Get("/health", HealthCheck)               // kubernetes health check
}

// @title Ortelius v11 Package Microservice
// @version 11.0.0
// @description RestAPI for the package Object
// @description ![Release](https://img.shields.io/github/v/release/ortelius/scec-deppkg?sort=semver)
// @description ![license](https://img.shields.io/github/license/ortelius/.github)
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

	fetchAndParseLicenses(licensesMap)
	setupRoutes(app) // define the routes for this microservice

	if err := app.Listen(port); err != nil { // start listening for incoming connections
		logger.Sugar().Fatalf("Failed get the microservice running: %v", err)
	}
}
