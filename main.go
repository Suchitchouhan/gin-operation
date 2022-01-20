package main

import (
	"gcurd/controllers"
	"gcurd/middlewares"
	"gcurd/models"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	models.ConnectDatabase()
	r.Use(gin.Logger())
	r.Static("/media", "./media")
	r.MaxMultipartMemory = 8 << 20
	r.POST("/signup", controllers.SignUp)
	r.POST("/signin", controllers.SignIn)
	r.POST("/CheckToken", controllers.CheckToken)
	r.GET("/GetAllBook", controllers.GetAllBook)

	authorized := r.Group("/v")
	authorized.Use(middlewares.TokenAuthMiddleware())
	authorized.GET("/Home", controllers.Home)
	authorized.GET("/GetBook", controllers.GetBook)
	authorized.POST("/AddBook", controllers.AddBook)
	authorized.GET("/DeleteBook/:Book_Id", controllers.DeleteBook)
	r.Run(":8000")
}
