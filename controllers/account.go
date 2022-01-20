package controllers

import (
	"fmt"
	"gcurd/models"
	"gcurd/payload"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const secretkey string = "jn)*hur7x$59tg!lrzosa_c#em)u2yelv%8%*v_j^36ymw"

type CreateAccount struct {
	Email     string `json:"email" binding:"required"`
	Firstname string `json:"firstname" binding:"required"`
	Lastname  string `json:"lastname" binding:"required"`
	Password  string `json:"password" binding:"required"`
}

type LoginPayload struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(userpassword string, providedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(userpassword), []byte(providedPassword))
	if err == nil {
		return true
	} else {
		return false
	}
}

func DecodeJwt(tokenStr string) (jwt.MapClaims, bool) {
	hmacSecret := []byte(secretkey)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return hmacSecret, nil
	})
	if err != nil {
		return nil, false
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, true
	} else {
		log.Printf("Invalid JWT Token")
		return nil, false
	}
}

func GenerateJWT(email string, Password string) (string, error) {
	var mySigningKey = []byte(secretkey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["email"] = email
	claims["password"] = Password
	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		fmt.Printf("Something Went Wrong: %s", err.Error())
		return "", err
	}
	return tokenString, nil
}

func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func SignUp(c *gin.Context) {
	var Account models.Account
	var CreateAccount CreateAccount
	if err := c.ShouldBindJSON(&CreateAccount); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if result := models.DB.Where("Email = ?", CreateAccount.Email).First(&Account).RowsAffected; result == 0 {
		bytes_password, err_password := HashPassword(CreateAccount.Password)
		if err_password != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Something worng"})
			return
		}
		AccountO := models.Account{Email: CreateAccount.Email, Firstname: CreateAccount.Firstname, Lastname: CreateAccount.Lastname, Password: bytes_password}
		models.DB.Create(&AccountO)
		c.JSON(http.StatusOK, gin.H{"message": "Account has been successfully created."})

	} else {
		c.JSON(http.StatusOK, gin.H{"message": "Email is already Exists."})
	}

}

func SignIn(c *gin.Context) {
	var LoginPayload LoginPayload
	var Account models.Account
	if err := c.ShouldBindJSON(&LoginPayload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if result := models.DB.Where("Email = ?", LoginPayload.Email).First(&Account).RowsAffected; result == 1 {
		if CheckPasswordHash(Account.Password, LoginPayload.Password) {
			token, err := GenerateJWT(LoginPayload.Email, LoginPayload.Password)
			if err == nil {
				c.JSON(http.StatusOK, gin.H{"message": "success", "token": token})
				return
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Error In generating JWT Token"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Incorrect Password"})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Email is not exists"})
		return
	}
}

func CheckToken(c *gin.Context) {
	var Account models.Account
	token := c.PostForm("token")
	clim, bool_e := DecodeJwt(token)
	if !bool_e {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Token is not valid"})
		return
	}

	if result := models.DB.Where("Email = ?", clim["email"]).First(&Account).RowsAffected; result == 1 {
		if CheckPasswordHash(Account.Password, fmt.Sprint(clim["password"])) {
			c.JSON(http.StatusOK, gin.H{"message": "Token is valid", "token": token})
			return
		}
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "success", "token": token})
		return
	}
}

func Home(c *gin.Context) {
	log.Println("home")
	Account := c.MustGet("Account").(models.Account)
	log.Println(Account.Firstname, " ", Account.Lastname)
	c.JSON(http.StatusOK, gin.H{"message": "hello " + Account.Firstname + " " + Account.Lastname})
}

func AddBook(c *gin.Context) {
	Account := c.MustGet("Account").(models.Account)
	Name := c.PostForm("Name")
	Image, err := c.FormFile("Image")
	Description := c.PostForm("Description")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   err,
			"message": "Failed to upload",
		})
		return
	}
	if Name == "" || Description == "" {
		c.JSON(http.StatusBadRequest, gin.H{"Message": "Name , Image , Description is required"})
		return
	}
	renamed_filed := "media/book/" + fmt.Sprint(time.Now().Unix()) + RandomString(10) + Image.Filename
	if err := c.SaveUploadedFile(Image, renamed_filed); err == nil {
		book := models.Book{Name: Name, Image: renamed_filed, Description: Description, Account_ID: Account.ID, Account: Account}
		models.DB.Create(&book)
		c.JSON(http.StatusOK, gin.H{"message": "Book has been added"})
		return
	} else {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "Unable to save the file",
			"error":   err.Error(),
		})
		return
	}
}

func GetBook(c *gin.Context) {
	Account := c.MustGet("Account").(models.Account)
	var SendBook []payload.SendBook
	result := models.DB.Raw("SELECT ID,Name,Image,Description,Account_ID FROM Books WHERE Account_ID = ?", Account.ID).Scan(&SendBook)
	// log.Println(result.RowsAffected)
	// log.Println(result.Error)
	if result.Error == nil {
		c.JSON(http.StatusOK, gin.H{"data": SendBook})
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"message": "Unable to save the file",
			"error":   result.Error,
		})
	}
}

func DeleteBook(c *gin.Context) {
	var book models.Book
	Account := c.MustGet("Account").(models.Account)
	Book_ID := c.Param("Book_Id")
	result := models.DB.Where("ID = ? AND Account_ID = ?", Book_ID, Account.ID).Delete(&book)
	if result.Error == nil {
		c.JSON(http.StatusOK, gin.H{"message": "Book has been successfully deleted"})
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"message": "Unable to save the file",
			"error":   result.Error,
		})
	}
}

func GetAllBook(c *gin.Context) {
	var SendBook []payload.SendBook
	result := models.DB.Raw("SELECT ID,Name,Image,Description,Account_ID FROM Books").Scan(&SendBook)
	if result.Error == nil {
		c.JSON(http.StatusOK, gin.H{"data": SendBook})
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"message": "Unable to save the file",
			"error":   result.Error,
		})
	}
}
