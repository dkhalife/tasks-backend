package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"dkhalife.com/tasks/core/backend"
	"dkhalife.com/tasks/core/config"
	"dkhalife.com/tasks/core/frontend"
	auth "dkhalife.com/tasks/core/internal/middleware/auth"
	"dkhalife.com/tasks/core/internal/migrations"
	database "dkhalife.com/tasks/core/internal/utils/database"
	"dkhalife.com/tasks/core/internal/utils/email"
	utils "dkhalife.com/tasks/core/internal/utils/middleware"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap/zapcore"
	"gorm.io/gorm"

	apis "dkhalife.com/tasks/core/internal/apis"
	lRepo "dkhalife.com/tasks/core/internal/repos/label"
	nRepo "dkhalife.com/tasks/core/internal/repos/notifier"
	tRepo "dkhalife.com/tasks/core/internal/repos/task"
	uRepo "dkhalife.com/tasks/core/internal/repos/user"
	"dkhalife.com/tasks/core/internal/services/housekeeper"
	logging "dkhalife.com/tasks/core/internal/services/logging"
	notifier "dkhalife.com/tasks/core/internal/services/notifications"
	"dkhalife.com/tasks/core/internal/services/scheduler"
	migration "dkhalife.com/tasks/core/internal/utils/migration"
)

func main() {
	cfg := config.LoadConfig()
	level, err := zapcore.ParseLevel(cfg.Server.LogLevel)
	if err != nil {
		level = zapcore.WarnLevel
	}

	logging.SetConfig(&logging.Config{
		Encoding:    "console",
		Level:       level,
		Development: level == zapcore.DebugLevel,
	})

	app := fx.New(
		fx.Supply(cfg),
		fx.Supply(logging.DefaultLogger().Desugar()),
		fx.WithLogger(func() fxevent.Logger {
			return &fxevent.NopLogger
		}),

		fx.Provide(auth.NewAuthMiddleware),

		fx.Provide(database.NewDatabase),
		fx.Provide(tRepo.NewTaskRepository),
		fx.Provide(apis.TasksAPI),
		fx.Provide(uRepo.NewUserRepository),
		fx.Provide(nRepo.NewNotificationRepository),
		fx.Provide(apis.UsersAPI),

		// add services
		fx.Provide(notifier.NewNotifier),
		fx.Provide(housekeeper.NewPasswordResetCleaner),
		fx.Provide(housekeeper.NewAppTokenCleaner),

		// Rate limiter
		fx.Provide(utils.NewRateLimiter),

		// add email sender:
		fx.Provide(email.NewEmailSender),
		// add handlers also
		fx.Provide(newServer),
		fx.Provide(scheduler.NewScheduler),

		// Labels:
		fx.Provide(lRepo.NewLabelRepository),
		fx.Provide(apis.LabelsAPI),
		fx.Provide(apis.LogsAPI),

		fx.Provide(frontend.NewHandler),
		fx.Provide(backend.NewHandler),

		fx.Invoke(
			apis.TaskRoutes,
			apis.UserRoutes,
			apis.LabelRoutes,
			apis.LogRoutes,
			frontend.Routes,
			backend.Routes,
		),
	)

	if err := app.Err(); err != nil {
		log.Fatal(err)
	}

	app.Run()

}

func newServer(lc fx.Lifecycle, cfg *config.Config, db *gorm.DB, bgScheduler *scheduler.Scheduler) *gin.Engine {
	if cfg.Server.LogLevel == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowCredentials = true
	config.AddAllowHeaders("Authorization", "secretkey")
	r.Use(cors.New(config))
	r.Use(utils.RequestLogger())

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			logging.FromContext(ctx).Info("Starting server")

			if cfg.Database.Migration {
				if err := migration.Migration(db); err != nil {
					return fmt.Errorf("failed to auto-migrate: %s", err.Error())
				}

				if err := migrations.Run(ctx, db); err != nil {
					return fmt.Errorf("failed to run migrations: %s", err.Error())
				}
			}

			bgScheduler.Start(context.Background())

			go func() {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log := logging.FromContext(ctx)
					log.Fatalf("listen: %s\n", err)
				}
			}()

			return nil
		},
		OnStop: func(ctx context.Context) error {
			if err := srv.Shutdown(ctx); err != nil {
				log := logging.FromContext(ctx)
				log.Fatalf("Server Shutdown: %s", err)
			} else {
				log := logging.FromContext(ctx)
				log.Info("Server stopped")
			}
			return nil
		},
	})

	return r
}
