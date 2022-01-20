package middlewares

import (
	"fmt"
	"gcurd/controllers"
	"gcurd/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

// func respondWithError(c *gin.Context, code int, message interface{}) {
// 	c.AbortWithStatusJSON(code, gin.H{"error": message})
// }

func TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var Account models.Account
		uers_token := c.Request.Header["Token"]
		clim, bool_e := controllers.DecodeJwt(uers_token[0])
		if !bool_e {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "API token required .or Token is not valid"})
			return
		}
		if result := models.DB.Where("Email = ?", clim["email"]).First(&Account).RowsAffected; result == 1 {
			if controllers.CheckPasswordHash(Account.Password, fmt.Sprint(clim["password"])) {
				c.Set("Account", Account)
				c.Next()
			}
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization is required"})
			return
		}

	}
}
