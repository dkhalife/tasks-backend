package repos

import (
	"context"
	"fmt"
	"time"

	"dkhalife.com/tasks/core/internal/models"
)

func (s *UserTestSuite) TestIsAppTokenValid() {
	ctx := context.Background()

	testUser := &models.User{
		Email:     "test@example.com",
		Password:  "hashedpassword",
		CreatedAt: time.Now(),
	}

	err := s.DB.Create(testUser).Error
	s.Require().NoError(err)

	// Create a token
	token := &models.AppToken{
		UserID:    testUser.ID,
		Name:      "Test Token",
		Token:     "valid-token-123",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Scopes:    []string{"task:read"},
	}

	err = s.DB.Create(token).Error
	s.Require().NoError(err)

	// Test with valid token
	isValid, err := s.repo.IsAppTokenValid(ctx, "valid-token-123")
	s.Require().NoError(err)
	s.True(isValid, "Valid token should be recognized")

	// Test with nonexistent token
	isValid, err = s.repo.IsAppTokenValid(ctx, "nonexistent-token")
	s.Require().NoError(err)
	s.False(isValid, "Nonexistent token should return false")

	// Delete the token
	err = s.repo.DeleteAppToken(ctx, testUser.ID, s.idToString(token.ID))
	s.Require().NoError(err)

	// Verify deleted token is no longer valid
	isValid, err = s.repo.IsAppTokenValid(ctx, "valid-token-123")
	s.Require().NoError(err)
	s.False(isValid, "Deleted token should be invalid")
}

func (s *UserTestSuite) idToString(id int) string {
	return fmt.Sprintf("%d", id)
}