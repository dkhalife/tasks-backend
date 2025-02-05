package migration

import (
	"fmt"
	"os"

	"donetick.com/core/config"
	migrations "donetick.com/core/internal/migrations"
	lModel "donetick.com/core/internal/models/label"
	nModel "donetick.com/core/internal/models/notifier"
	tModel "donetick.com/core/internal/models/task"
	uModel "donetick.com/core/internal/models/user"
	migrate "github.com/rubenv/sql-migrate"
	"gorm.io/gorm"
)

func Migration(db *gorm.DB) error {
	if err := db.AutoMigrate(uModel.User{}, tModel.Task{},
		tModel.TaskHistory{},
		nModel.Notification{},
		uModel.UserPasswordReset{},
		uModel.APIToken{},
		uModel.UserNotificationTarget{},
		lModel.Label{},
		tModel.TaskLabels{},
		migrations.Migration{},
	); err != nil {
		return err
	}

	return nil
}

func MigrationScripts(gormDB *gorm.DB, cfg *config.Config) error {
	migrations := &migrate.EmbedFileSystemMigrationSource{
		Root: "migrations",
	}

	path := os.Getenv("DT_SQLITE_PATH")
	if path == "" {
		path = "donetick.db"
	}

	db, err := gormDB.DB()
	if err != nil {
		return err
	}

	n, err := migrate.Exec(db, "sqlite3", migrations, migrate.Up)
	if err != nil {
		return err
	}
	fmt.Printf("Applied %d migrations!\n", n)
	return nil
}
