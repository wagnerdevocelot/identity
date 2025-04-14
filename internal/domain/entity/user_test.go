// Package entity_test contains tests for the entity package
package entity_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"identity-go/internal/domain/entity"
)

func TestNewUser(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		id             string
		username       string
		email          string
		hashedPassword string
		wantError      error
	}{
		{
			name:           "Valid user",
			id:             "123",
			username:       "testuser",
			email:          "test@example.com",
			hashedPassword: "hashedpassword",
			wantError:      nil,
		},
		{
			name:           "Empty username",
			id:             "123",
			username:       "",
			email:          "test@example.com",
			hashedPassword: "hashedpassword",
			wantError:      entity.ErrInvalidUsername,
		},
		{
			name:           "Empty email",
			id:             "123",
			username:       "testuser",
			email:          "",
			hashedPassword: "hashedpassword",
			wantError:      entity.ErrInvalidEmail,
		},
		{
			name:           "Invalid email format",
			id:             "123",
			username:       "testuser",
			email:          "invalid-email",
			hashedPassword: "hashedpassword",
			wantError:      entity.ErrInvalidEmail,
		},
		{
			name:           "Empty password",
			id:             "123",
			username:       "testuser",
			email:          "test@example.com",
			hashedPassword: "",
			wantError:      entity.ErrInvalidPassword,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			user, err := entity.NewUser(tc.id, tc.username, tc.email, tc.hashedPassword)

			if tc.wantError != nil {
				assert.ErrorIs(t, err, tc.wantError)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, tc.id, user.ID)
				assert.Equal(t, tc.username, user.Username)
				assert.Equal(t, tc.email, user.Email)
				assert.Equal(t, tc.hashedPassword, user.HashedPassword)
				assert.True(t, user.Active)
				assert.WithinDuration(t, time.Now(), user.CreatedAt, time.Second)
				assert.WithinDuration(t, time.Now(), user.UpdatedAt, time.Second)
				assert.Nil(t, user.LastLoginAt)
			}
		})
	}
}

func TestUser_IsActive(t *testing.T) {
	t.Parallel()

	user := &entity.User{Active: true}
	assert.True(t, user.IsActive())

	user.Active = false
	assert.False(t, user.IsActive())
}

func TestUser_SetActive(t *testing.T) {
	t.Parallel()

	user := &entity.User{Active: false}
	beforeUpdate := user.UpdatedAt

	time.Sleep(5 * time.Millisecond) // Ensure time difference
	user.SetActive(true)

	assert.True(t, user.Active)
	assert.True(t, user.UpdatedAt.After(beforeUpdate))
}

func TestUser_SetLastLogin(t *testing.T) {
	t.Parallel()

	user := &entity.User{}
	beforeUpdate := user.UpdatedAt
	loginTime := time.Now()

	time.Sleep(5 * time.Millisecond) // Ensure time difference
	user.SetLastLogin(loginTime)

	assert.NotNil(t, user.LastLoginAt)
	assert.Equal(t, loginTime, *user.LastLoginAt)
	assert.True(t, user.UpdatedAt.After(beforeUpdate))
}

func TestUser_FullName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		firstName string
		lastName  string
		want      string
	}{
		{"John", "Doe", "John Doe"},
		{"", "Doe", " Doe"},
		{"John", "", "John "},
		{"", "", " "},
	}

	for _, tc := range testCases {
		user := &entity.User{
			FirstName: tc.firstName,
			LastName:  tc.lastName,
		}

		assert.Equal(t, tc.want, user.FullName())
	}
}

func TestUser_UpdateProfile(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		firstName string
		lastName  string
		email     string
		wantError bool
	}{
		{
			name:      "Valid update",
			firstName: "John",
			lastName:  "Doe",
			email:     "john.doe@example.com",
			wantError: false,
		},
		{
			name:      "Empty email",
			firstName: "John",
			lastName:  "Doe",
			email:     "",
			wantError: true,
		},
		{
			name:      "Invalid email format",
			firstName: "John",
			lastName:  "Doe",
			email:     "invalid-email",
			wantError: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			user := &entity.User{
				FirstName: "Original",
				LastName:  "Name",
				Email:     "original@example.com",
			}

			beforeUpdate := user.UpdatedAt
			time.Sleep(5 * time.Millisecond) // Ensure time difference

			err := user.UpdateProfile(tc.firstName, tc.lastName, tc.email)

			if tc.wantError {
				assert.Error(t, err)
				assert.Equal(t, entity.ErrInvalidEmail, err)
				assert.Equal(t, "original@example.com", user.Email)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.firstName, user.FirstName)
				assert.Equal(t, tc.lastName, user.LastName)
				assert.Equal(t, tc.email, user.Email)
				assert.True(t, user.UpdatedAt.After(beforeUpdate))
			}
		})
	}
}

func TestUser_ChangePassword(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		hashedPassword string
		wantError      error
	}{
		{
			name:           "Valid password change",
			hashedPassword: "newhashedpassword",
			wantError:      nil,
		},
		{
			name:           "Empty password",
			hashedPassword: "",
			wantError:      entity.ErrInvalidPassword,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			user := &entity.User{
				HashedPassword: "originalhashedpassword",
			}

			beforeUpdate := user.UpdatedAt
			time.Sleep(5 * time.Millisecond) // Ensure time difference

			err := user.ChangePassword(tc.hashedPassword)

			if tc.wantError != nil {
				assert.ErrorIs(t, err, tc.wantError)
				assert.Equal(t, "originalhashedpassword", user.HashedPassword)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.hashedPassword, user.HashedPassword)
				assert.True(t, user.UpdatedAt.After(beforeUpdate))
			}
		})
	}
}
