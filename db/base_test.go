package db

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/shlin168/go-nvd/nvd/schema"
)

func TestResult(t *testing.T) {
	result := Result[schema.Cve]{
		Total: 5,
		Start: 0,
		Size:  5,
		Entries: []schema.Cve{
			{CVEID: "CVE-2020-1234", Published: "2023-08-14T00:00:00.000"},
			{CVEID: "CVE-2020-1235", Published: "2023-08-15T00:00:00.000"},
			{CVEID: "CVE-2020-1236", Published: "2023-08-16T00:00:00.000"},
			{CVEID: "CVE-2020-1237", Published: "2023-08-17T00:00:00.000"},
			{CVEID: "CVE-2020-1238", Published: "2023-08-18T00:00:00.000"},
		},
	}

	// test filter
	fresult := result.Filter(func(item schema.Cve) bool {
		return item.CVEID > "CVE-2020-1236"
	})
	assert.Equal(t, 2, fresult.Total)
	assert.Equal(t, 2, len(fresult.Entries))

	// test sort
	fresult.Sort(func(i, j int) bool {
		return fresult.Entries[i].Published > fresult.Entries[j].Published
	})
	assert.Equal(t, "CVE-2020-1238", fresult.Entries[0].CVEID)
	assert.Equal(t, "CVE-2020-1237", fresult.Entries[1].CVEID)

	// test pagination
	presult := result.GetPaginated(0, 2)
	assert.Equal(t, 5, presult.Total)
	assert.Equal(t, 0, presult.Start)
	assert.Equal(t, 2, presult.Size)
	assert.Equal(t, 2, len(presult.Entries))

	presult = result.GetPaginated(2, 2)
	assert.Equal(t, 5, presult.Total)
	assert.Equal(t, 2, presult.Start)
	assert.Equal(t, 2, presult.Size)
	assert.Equal(t, 2, len(presult.Entries))

	presult = result.GetPaginated(3, 2)
	assert.Equal(t, 5, presult.Total)
	assert.Equal(t, 3, presult.Start)
	assert.Equal(t, 2, presult.Size)
	assert.Equal(t, 2, len(presult.Entries))

	presult = result.GetPaginated(3, 4)
	assert.Equal(t, 5, presult.Total)
	assert.Equal(t, 3, presult.Start)
	assert.Equal(t, 2, presult.Size)
	assert.Equal(t, 2, len(presult.Entries))

	presult = result.GetPaginated(5, 3)
	assert.Equal(t, 5, presult.Total)
	assert.Equal(t, 5, presult.Start)
	assert.Equal(t, 0, presult.Size)
	assert.Equal(t, 0, len(presult.Entries))
}

func TestQueryConfig(t *testing.T) {
	for _, invalidOpts := range [][]QueryOptions{
		{Size(-2)},
		{Size(0)},
		{StartWith(-1)},
	} {
		_, err := GetQueryConfig(invalidOpts...)
		assert.Error(t, err)
	}

	for _, validOpts := range [][]QueryOptions{
		{StartWith(2), Size(GetSizeUnlimited)},
		{StartWith(2), Size(100)},
		{StartWith(0), Size(100)},
		{Size(100)},
		{},
	} {
		_, err := GetQueryConfig(validOpts...)
		assert.NoError(t, err)
	}
}
