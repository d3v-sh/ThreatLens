package query

import (
	"encoding/json"
	"fmt"
	"threatlens/internal/models"
	"os"
)

func LoadQueries(filename string) (*models.QuerySet, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read queries: %v", err)
	}
	var querySet models.QuerySet
	if err := json.Unmarshal(data, &querySet); err != nil {
		return nil, fmt.Errorf("failed to parse queries file: %v", err)
	}
	return &querySet, nil
}

func GetQueryByName(queries []models.Query, name string) *models.Query {
	for _, q := range queries {
		if q.Name == name && q.Enabled {
			return &q
		}
	}
	return nil
}
