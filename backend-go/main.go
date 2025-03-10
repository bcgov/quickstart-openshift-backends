package main

import (
	"time"

	_ "github.com/bcgov/quickstart-openshift-backends/backend-go/docs"
	"github.com/bcgov/quickstart-openshift-backends/backend-go/src"
	"github.com/bcgov/quickstart-openshift-backends/backend-go/src/v1/structs"
	"github.com/devfeel/mapper"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/sirupsen/logrus"
)

var startTime time.Time

func init() {
	startTime = time.Now()
	_ = mapper.Register(&structs.User{})
	_ = mapper.Register(&structs.UserAddress{})
}

func main() {
	app := src.App()
	err := app.Listen(":3000")
	if err != nil {
		logrus.Fatalf("Error: %v", err)
		return
	}

	logrus.Infof("Process startup took %s", time.Since(startTime))
}
