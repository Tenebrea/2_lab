from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

def test_read_main():
    response = client.get("/")
    assert response.status_code == 200

def test_get_users():
    response = client.get("/users/")
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    assert data[0]["username"] == "string"

def test_create_user():
    response = client.post("/register/", json={"username": "testuser", "email": "testuser@example.com", "full_name": "Test User", "password": "password123"},)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["email"] == "testuser@example.com"

def test_register_new_user():
    new_user_data = {
        "username": "newuser",
        "email": "newuser@example.com",
        "full_name": "New User",
        "password": "secure_password_123"
    }
    
    response = client.post("/register/", json=new_user_data)
    
    assert response.status_code == 200
    user_data = response.json()
    assert user_data["username"] == "newuser"
    assert user_data["email"] == "newuser@example.com"

def test_duplicate_username_registration():
    duplicate_user_data = {
        "username": "existinguser",
        "email": "duplicate@example.com",
        "full_name": "Duplicate User",
        "password": "another_secure_password"
    }
    
    response = client.post("/register/", json=duplicate_user_data)
    
    assert response.status_code == 400
    error_message = response.json()["detail"]
    assert "Username already exists." in error_message

def test_duplicate_email_registration():
    duplicate_email_data = {
        "username": "uniqueuser",
        "email": "already_used@example.com",
        "full_name": "Unique User",
        "password": "very_secure_password"
    }
    
    response = client.post("/register/", json=duplicate_email_data)
    
    assert response.status_code == 400
    error_message = response.json()["detail"]
    assert "Email address is already registered." in error_message

def test_successful_login():
    login_data = {"username": "registereduser", "password": "correct_password"}
    
    response = client.post("/login/token", data=login_data)
    
    assert response.status_code == 200
    token_response = response.json()
    assert "access_token" in token_response and "token_type" in token_response

def test_failed_login_incorrect_username():
    wrong_login_data = {"username": "nonexistentuser", "password": "any_password"}
    
    response = client.post("/login/token", data=wrong_login_data)
    
    assert response.status_code == 401
    error_message = response.json()["detail"]
    assert "Incorrect username or password." in error_message

def test_failed_login_wrong_password():
    incorrect_password_data = {"username": "validuser", "password": "invalid_password"}
    
    response = client.post("/login/token", data=incorrect_password_data)
    
    assert response.status_code == 401
    error_message = response.json()["detail"]
    assert "Incorrect username or password." in error_message

def test_invalid_or_expired_token():
    expired_token_headers = {"Authorization": f"Bearer invalid_token_here"}
    
    response = client.get("/users/", headers=expired_token_headers)
    
    assert response.status_code == 401
    error_message = response.json()["detail"]
    assert "Could not validate credentials" in error_message

def test_get_all_users():
    response = client.get("/users/")
    
    assert response.status_code == 200
    users_list = response.json()
    assert isinstance(users_list, list)
    assert len(users_list) >= 1  
    first_user = users_list[0]
    assert "username" in first_user and "email" in first_user

def test_get_current_user_with_valid_token():
    valid_token_headers = {"Authorization": f"Bearer valid_access_token"}
    
    response = client.get("/users/me", headers=valid_token_headers)
    
    assert response.status_code == 200
    current_user = response.json()
    assert "username" in current_user and "email" in current_user

def test_update_user_details():
    update_data = {"full_name": "Updated Full Name", "email": "updated_email@example.com"}
    valid_token_headers = {"Authorization": f"Bearer valid_access_token"}
    
    response = client.put("/users/update_profile", json=update_data, headers=valid_token_headers)
    
    assert response.status_code == 200
    updated_user = response.json()
    assert updated_user["full_name"] == "Updated Full Name"
    assert updated_user["email"] == "updated_email@example.com"

def test_update_user_with_invalid_data():
    invalid_update_data = {"full_name": "", "email": ""}
    valid_token_headers = {"Authorization": f"Bearer valid_access_token"}
    
    response = client.put("/users/update_profile", json=invalid_update_data, headers=valid_token_headers)
    
    assert response.status_code == 422
    validation_errors = response.json()["detail"]
    assert any("field required" in err["msg"] for err in validation_errors)

def test_unauthorized_update_user():
    unauthorized_headers = {}
    
    response = client.put("/users/update_profile", json={}, headers=unauthorized_headers)
    
    assert response.status_code == 401
    error_message = response.json()["detail"]
    assert "Not authenticated" in error_message

def test_delete_user():
    valid_token_headers = {"Authorization": f"Bearer valid_access_token"}
    
    response = client.delete("/users/delete_account", headers=valid_token_headers)
    
    assert response.status_code == 200
    delete_confirmation = response.json()
    assert "User deleted successfully" in delete_confirmation["message"]

def test_repeated_deletion_of_deleted_user():
    valid_token_headers = {"Authorization": f"Bearer valid_access_token"}
    
    response = client.delete("/users/delete_account", headers=valid_token_headers)
    
    assert response.status_code == 404
    error_message = response.json()["detail"]
    assert "User does not exist." in error_message