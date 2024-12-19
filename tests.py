import unittest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from main import app, get_db
from database import Base
import schemas
import security

# Test Database Configuration
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_database.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


class UserManagementTestCase(unittest.TestCase):
    def setUp(self):
        # Create tables
        Base.metadata.create_all(bind=engine)

        # Create test client
        self.client = TestClient(app)

        # Prepare test data
        self.test_user = {
            "username": "testuser",
            "email": "testuser@example.com",
            "password": "strongpassword123",
            "full_name": "Test User",
        }

    def tearDown(self):
        # Drop all tables after each test
        Base.metadata.drop_all(bind=engine)

    def test_register_user_success(self):
        # Test successful user registration
        response = self.client.post("/register", json=self.test_user)

        self.assertEqual(response.status_code, 200)
        user_data = response.json()

        self.assertEqual(user_data["username"], self.test_user["username"])
        self.assertEqual(user_data["email"], self.test_user["email"])
        self.assertEqual(user_data["full_name"], self.test_user["full_name"])
        self.assertEqual(user_data["address"], self.test_user["address"])

    def test_register_duplicate_user(self):
        # Register first user
        self.client.post("/register", json=self.test_user)

        # Try registering same user again
        response = self.client.post("/register", json=self.test_user)

        self.assertEqual(response.status_code, 400)
        self.assertIn("already registered", response.json()["detail"])

    def test_login_success(self):
        # First register a user
        self.client.post("/register", json=self.test_user)

        # Then attempt login
        login_data = {
            "username": self.test_user["username"],
            "password": self.test_user["password"],
        }
        response = self.client.post("/login", json=login_data)

        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())
        self.assertEqual(response.json()["token_type"], "bearer")

    def test_login_invalid_credentials(self):
        # Register a user first
        self.client.post("/register", json=self.test_user)

        # Try login with wrong password
        login_data = {
            "username": self.test_user["username"],
            "password": "wrongpassword",
        }
        response = self.client.post("/login", json=login_data)

        self.assertEqual(response.status_code, 401)
        self.assertIn("Incorrect username", response.json()["detail"])

    def test_update_user_profile(self):
        # Register and login to get token
        self.client.post("/register", json=self.test_user)
        login_response = self.client.post(
            "/login",
            json={
                "username": self.test_user["username"],
                "password": self.test_user["password"],
            },
        )
        access_token = login_response.json()["access_token"]

        # Update profile
        update_data = {
            "full_name": "Updated Test User",
            "email": "updated_testuser@example.com",
        }
        response = self.client.put(
            "/update",
            json=update_data,
            headers={"Authorization": f"Bearer {access_token}"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["full_name"], "Updated Test User")
        self.assertEqual(response.json()["email"], "updated_testuser@example.com")

    def test_update_user_unauthorized(self):
        # Try to update without authentication
        update_data = {"full_name": "Updated Test User"}
        response = self.client.put("/update", json=update_data)

        self.assertEqual(response.status_code, 401)

    def test_password_hashing(self):
        # Verify that passwords are hashed and not stored in plain text
        password = "test_password"
        hashed_password = security.get_password_hash(password)

        self.assertNotEqual(password, hashed_password)
        self.assertTrue(security.verify_password(password, hashed_password))

    def test_update_duplicate_email(self):
        # Register two users
        first_user = {
            "username": "firstuser",
            "email": "first@example.com",
            "password": "password123",
        }
        second_user = {
            "username": "seconduser",
            "email": "second@example.com",
            "password": "password456",
        }

        # Register both users
        self.client.post("/register", json=first_user)
        self.client.post("/register", json=second_user)

        # Login as first user
        first_login = self.client.post(
            "/login",
            json={
                "username": first_user["username"],
                "password": first_user["password"],
            },
        )
        first_token = first_login.json()["access_token"]

        # Try to update first user's email to second user's email
        update_data = {"email": second_user["email"]}
        response = self.client.put(
            "/update",
            json=update_data,
            headers={"Authorization": f"Bearer {first_token}"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("Email already in use", response.json()["detail"])


# Optional: Add this if you want to run tests directly
if __name__ == "__main__":
    unittest.main()
