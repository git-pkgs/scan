package scan_test

import (
	"fmt"
	"log"

	"github.com/git-pkgs/scan"
)

func ExampleDatabase_Scan() {
	db, err := scan.Compile(
		&scan.Pattern{Expression: `token=[a-z0-9]{8}`, ID: 1, Flags: scan.SingleMatch | scan.SomLeftMost},
		&scan.Pattern{Expression: `code=[0-9]{4}`, ID: 2, Flags: scan.SingleMatch | scan.SomLeftMost},
	)
	if err != nil {
		log.Fatal(err)
	}

	scratch := scan.NewScratch(db)
	err = db.Scan([]byte("token=abc12345 code=1234"), scratch, func(match scan.Match) error {
		fmt.Printf("%d %d:%d\n", match.ID, match.From, match.To)
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	// Output:
	// 1 0:14
	// 2 15:24
}

func ExampleDatabase_Match() {
	db, err := scan.Compile(&scan.Pattern{Expression: `token=[a-z0-9]{8}`})
	if err != nil {
		log.Fatal(err)
	}
	scratch := scan.NewScratch(db)
	matched, err := db.Match([]byte("token=abc12345"), scratch)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(matched)
	// Output: true
}

func ExampleDatabase_Marshal() {
	db, err := scan.Compile(&scan.Pattern{Expression: `token=[a-z0-9]{8}`})
	if err != nil {
		log.Fatal(err)
	}
	compiled, err := db.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	loaded, err := scan.UnmarshalDatabase(compiled)
	if err != nil {
		log.Fatal(err)
	}
	matched, err := loaded.Match([]byte("token=abc12345"), scan.NewScratch(loaded))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(matched)
	// Output: true
}

func ExampleScratch_Clone() {
	db, err := scan.Compile(&scan.Pattern{Expression: `token=[a-z0-9]{8}`})
	if err != nil {
		log.Fatal(err)
	}
	scratch := scan.NewScratch(db)
	inputs := [][]byte{[]byte("token=abc12345"), []byte("no match")}
	results := make(chan bool, len(inputs))
	for _, input := range inputs {
		workerScratch := scratch.Clone()
		go func() {
			matched, err := db.Match(input, workerScratch)
			if err != nil {
				log.Fatal(err)
			}
			results <- matched
		}()
	}
	matchedInputs := 0
	for range inputs {
		if <-results {
			matchedInputs++
		}
	}
	fmt.Println(matchedInputs)
	// Output: 1
}
