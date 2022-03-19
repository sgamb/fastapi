from datetime import timedelta

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from main import (ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, SECRET_KEY, JWTError,
                  UserInDB, app, authenticate_user, create_access_token,
                  fake_users_db, get_current_user, get_password_hash, jwt,
                  verify_password)

client = TestClient(app)


JohnDoe = UserInDB(**fake_users_db.get("johndoe"))


def test_read_root():
    """Smoke test"""
    response = client.get("/")
    assert response.status_code == 200


def test_get_password_hash():
    hashed_password = get_password_hash("secret")
    assert verify_password("secret", hashed_password)


def test_authenticate_user():
    user = authenticate_user(fake_users_db, "lennon", "secret")
    assert not user

    user = authenticate_user(fake_users_db, "johndoe", "password")
    assert not user

    user = authenticate_user(fake_users_db, "johndoe", "secret")
    assert user == JohnDoe


def test_create_access_token():
    data = {"sub": "johndoe"}
    token = create_access_token(data=data)
    payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    assert payload.get("sub") == data.get("sub")

    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(data=data, expires_delta=expires_delta)
    payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    assert payload.get("sub") == data.get("sub")


def test_get_current_user():
    token = create_access_token(data={})
    with pytest.raises(HTTPException):
        get_current_user(token=token)

    token = "gibberish"
    with pytest.raises(HTTPException):
        with pytest.raises(JWTError):
            get_current_user(token=token)

    data = {"sub": "anonymous"}
    token = create_access_token(data=data)
    with pytest.raises(HTTPException):
        get_current_user(token=token)

    data = {"sub": "johndoe"}
    token = create_access_token(data=data)
    user = get_current_user(token=token)
    assert user == JohnDoe


def test_login_for_access_token():
    response = client.post("/token", data={"username": "lennon", "password": "secret"})
    assert response.status_code == 401
    assert response.json().get("detail") == "Incorrect username or password"

    response = client.post("/token", data={"username": "johndoe", "password": "password"})
    assert response.status_code == 401
    assert response.json().get("detail") == "Incorrect username or password"

    response = client.post("/token", data={"username": "johndoe", "password": "secret"})
    assert response.status_code == 200


def test_read_emoticon():
    response = client.get("/emoticon/example")
    assert response.status_code == 401

    data = {"sub": "johndoe"}
    token = create_access_token(data=data)
    response = client.get("/emoticon/example/", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
