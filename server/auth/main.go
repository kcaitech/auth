package auth

func main() {
    r := gin.Default()
    
    authHandler := auth.NewAuthHandler(
        "your-client-id",
        "your-client-secret",
        "http://your-domain/auth/google/callback"
    )
    
    authHandler.RegisterRoutes(r)
    
    r.Run(":8080")
}