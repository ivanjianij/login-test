# login_test_backend  

A Spring Boot backend application that provides **JWT-based authentication** for:  
- Local accounts (email + password)  
- Third-party login (Google OAuth2)  

This service issues JWT access tokens and exposes APIs for login, registration, and OAuth2 authentication.  

---

## Setup  

Follow these steps to set up and run the project:  

1. **Start Docker Services**  
   Run the following command to create the PostgreSQL container:  
   ```bash
   docker compose up -d
   ```  
   > **Note**: The current configuration maps port `5434:5432`. If you have other Docker services using the same port, you may need to stop them first.  

2. **Configure `.env` File**  
   Create a `.env` file in the root directory of the project. This file will store sensitive keys required by `application.yml` such as the JWT secret and third-party API keys. Example:  
   ```env
   GOOGLE_CLIENT_ID=
   GOOGLE_CLIENT_SECRET=
   APP_JWT_SECRET=
   ```  

3. **Check Server Port**  
   Ensure the server port in `application.yml` is set to `8081`, since port `8080` is already in use by other Docker services.  

4. **Run the Application**  
   Use Maven to run the Spring Boot application:  
   ```bash
   mvn spring-boot:run
   ```

---

## API Endpoints  

### Authentication APIs  

- **Login**  
  ```http
  POST http://localhost:8081/api/auth
  ```  
  Request body (JSON):  
  ```json
  {
    "email": "example@email.com",
    "password": "yourpassword"
  }
  ```  

- **Register**  
  ```http
  POST http://localhost:8081/api/auth/users
  ```  
  Request body (JSON):  
  ```json
  {
    "email": "example@email.com",
    "password": "yourpassword",
    "name": "Your Name"
  }
  ```  

### Google OAuth2 Login  

- To test Google sign-in:  
  ```http
  GET http://localhost:8081/oauth2/authorization/google
  ```  
- Success should redirect you to the following url where it should display message and store in database
```json
{
    "message": "Login successful",
    "token": "token", 
    "email": "email", 
    "name": "name of user"
}
```
http://localhost:8081/login/oauth2/code/google?state=.....
---

## Notes  

- If an email is already registered (either via local account or Google OAuth2), you cannot create another account with the same email.  
- Users must sign in using the method originally used to register (local or third-party).  
