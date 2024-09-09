package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	vt "github.com/VirusTotal/vt-go"
	_ "github.com/joho/godotenv/autoload"
)

type Data struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	Links      Links      `json:"links"`
	Attributes Attributes `json:"attributes"`
}

type Links struct {
	Self string `json:"self"`
}

type Attributes struct {
	Reputation         int               `json:"reputation"`
	ThreatNames        []string          `json:"threat_names"`
	URL                string            `json:"url"`
	TotalVotes         TotalVotes        `json:"total_votes"`
	Categories         map[string]string `json:"categories"`
	LastSubmissionDate int64             `json:"last_submission_date"`
	Title              string            `json:"title"`
	TimesSubmitted     int               `json:"times_submitted"`
	LastAnalysisStats  LastAnalysisStats `json:"last_analysis_stats"`
}

type TotalVotes struct {
	Harmless  int `json:"harmless"`
	Malicious int `json:"malicious"`
}

type LastAnalysisStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
	Harmless   int `json:"harmless"`
	Timeout    int `json:"timeout"`
}

type Root struct {
	Data Data `json:"data"`
}

func parseJSON(input []byte) (*Root, error) {
	var result Root
	err := json.Unmarshal(input, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func URLFileAnalysis(url string) string {
	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", os.Getenv("APIKEY"))

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	return string(body)
}

var sha256 = flag.String("sha256", "", "SHA-256 of some file")

func main() {

	flag.Parse()

	if *sha256 == "" {
		fmt.Println("Must pass --sha256 argument.")
		os.Exit(0)
	}

	client := vt.NewClient(os.Getenv("APIKEY"))

	file, err := client.GetObject(vt.URL("files/%s", *sha256))
	if err != nil {
		log.Fatal(err)
	}

	ls, err := file.GetTime("last_submission_date")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("File %s was submitted for the last time on %v\n", file.ID(), ls)
	jsonData := URLFileAnalysis("https://www.virustotal.com/api/v3/urls/8d7167a29497052878712e36777cd5cfb82a626cd6abe431e808394d1eaac218")

	parsedData, err := parseJSON([]byte(jsonData))
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}

	// Print the parsed data
	//! UNCOMMENT TO SEE JSON IN CONSOLE
	//fmt.Printf("%+v\n", parsedData)

	f, err := os.Create("output.json")
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
	}
	defer f.Close()

	// Marshal the parsed data back to JSON
	jsonBytes, err := json.MarshalIndent(parsedData, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}

	// Write the JSON data to the file
	_, err = f.Write(jsonBytes)
	if err != nil {
		log.Fatalf("Error writing to file: %v", err)
	}

}
