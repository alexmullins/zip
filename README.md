This fork add support for Standard Zip Encryption.

The work is based on https://github.com/alexmullins/zip

Available encryption:
```
zip.StandardEncryption
zip.AES128Encryption
zip.AES192Encryption
zip.AES256Encryption
```

## Warning

Zip Standard Encryption isn't actually secure.
Unless you have to work with it, please use AES encryption instead.

## Example Encrypt Zip

```
package main

import (
	"bytes"
	"io"
	"log"
	"os"

	"github.com/yeka/zip"
)

func main() {
	contents := []byte("Hello World")
	fzip, err := os.Create(`./test.zip`)
	if err != nil {
		log.Fatalln(err)
	}
	zipw := zip.NewWriter(fzip)
	defer zipw.Close()
	w, err := zipw.Encrypt(`test.txt`, `golang`, zip.AES256Encryption)
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.Copy(w, bytes.NewReader(contents))
	if err != nil {
		log.Fatal(err)
	}
	zipw.Flush()
}
```

## Example Decrypt Zip

```
package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/yeka/zip"
)

func main() {
	r, err := zip.OpenReader("encrypted.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	for _, f := range r.File {
		if f.IsEncrypted() {
			f.SetPassword("12345")
		}

		r, err := f.Open()
		if err != nil {
			log.Fatal(err)
		}

		buf, err := ioutil.ReadAll(r)
		if err != nil {
			log.Fatal(err)
		}
		defer r.Close()

		fmt.Printf("Size of %v: %v byte(s)\n", f.Name, len(buf))
	}
}
```

### fileheader

```

func  StepDealZip(tmpFilesForZip []string, zipFilePath string, job YellowDogJob) (err error) {
	archive, err := os.Create(zipFilePath)
	if err != nil {
		return err
	}
	defer archive.Close()
	zipWriter := zip.NewWriter(archive)
	for _, file := range tmpFilesForZip {
		fileInfo, err := os.Stat(file)
		if err != nil {
			return err
		}
		body, err := ioutil.ReadFile(file)
		if err != nil {
			return err
		}
		var filename string
		fileNameSplit := strings.Split(fileInfo.Name(), ".")
		if fileNameSplit[2] == `pdf` {
			filename = "报表_" + fileNameSplit[1] + `.pdf`
		} else {
			for _, values := range job.RptTableDict {
				if values.Dish == fileNameSplit[0] {
					filename = fileNameSplit[1] + `_` + values.DishHuman + `.xlsx`
				}
			}
		}
		header := &zip.FileHeader{
			Name:   filename,
			Flags:  1 << 11, // 使用utf8编码
			Method: zip.Deflate,
		}
		if job.RptPwd != `` {
			header.SetPassword(job.RptPwd)
			header.SetEncryptionMethod(zip.StandardEncryption)
		}
		f, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = f.Write([]byte(body))
		if err != nil {
			return err
		}
	}
	if err = zipWriter.Close(); err != nil {
		return err
	}
	return nil
}

```

