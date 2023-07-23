package main

import (
	"ckks_ip/src/bmp"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func bmpRead(filename string) (head bmp.Header, body [][]bmp.Pixel) {
	fin, err := os.Open(filename)
	defer fin.Close()
	check(err)
	err = binary.Read(fin, binary.LittleEndian, &head)
	check(err)
	body = make([][]bmp.Pixel, head.Height)
	for i := 0; i < int(head.Height); i++ {
		body[i] = make([]bmp.Pixel, head.Width)
	}
	for i := 0; i < int(head.Height); i++ {
		for j := 0; j < int(head.Width); j++ {
			err = binary.Read(fin, binary.BigEndian, &body[i][j])
			check(err)
		}
	}
	return
}

func bmpWrite(filename string, head bmp.Header, body [][]bmp.Pixel) {
	fout, err := os.Create(filename)
	defer fout.Close()
	check(err)
	err = binary.Write(fout, binary.LittleEndian, head)
	check(err)
	for i := 0; i < int(head.Height); i++ {
		for j := 0; j < int(head.Width); j++ {
			err = binary.Write(fout, binary.BigEndian, body[i][j])
			check(err)
		}
	}
}

func grayscale(body *[][]bmp.Pixel) {
	for i := 0; i < len(*body); i++ {
		for j := 0; j < len((*body)[i]); j++ {
			temp := uint8(float64((*body)[i][j].B)*0.114 + float64((*body)[i][j].G)*0.587 + float64((*body)[i][j].R)*0.299)
			(*body)[i][j].B = temp
			(*body)[i][j].G = temp
			(*body)[i][j].R = temp
		}
	}
}

func pixelToArray(body [][]bmp.Pixel) (ret [][]float64) {
	h := len(body)
	w := len(body[0])
	ret = make([][]float64, h)
	for i := 0; i < h; i++ {
		ret[i] = make([]float64, w*9)
	}
	for i := 0; i < h; i++ {
		for j := 0; j < w; j++ {
			ret[i][j*3+0] = float64(body[i][j].B)
			ret[i][j*3+1] = float64(body[i][j].B)
			ret[i][j*3+2] = float64(body[i][j].B)
			ret[i][w*3+j*3+0] = float64(body[i][j].G)
			ret[i][w*3+j*3+1] = float64(body[i][j].G)
			ret[i][w*3+j*3+2] = float64(body[i][j].G)
			ret[i][w*6+j*3+0] = float64(body[i][j].R)
			ret[i][w*6+j*3+1] = float64(body[i][j].R)
			ret[i][w*6+j*3+2] = float64(body[i][j].R)
			// fmt.Println(i*w*3 + j*3 + 0)
		}
	}
	// fmt.Println(ret)
	return
}

func __arrayToPixel(arr [][]float64) (body [][]bmp.Pixel) {
	height := len(arr)
	width := len(arr[0]) / 9
	body = make([][]bmp.Pixel, height)
	for i := 0; i < int(height); i++ {
		body[i] = make([]bmp.Pixel, width)
	}
	for i := 0; i < int(height); i++ {
		for j := 0; j < int(width); j++ {
			body[i][j].B = uint8(arr[i][j*3])
			body[i][j].G = uint8(arr[i][width*3+j*3])
			body[i][j].R = uint8(arr[i][width*6+j*3])
		}
	}
	return
}

func arrayToPixel(arr [][]float64) (body [][]bmp.Pixel) {
	height := len(arr)
	width := len(arr[0]) / 3
	body = make([][]bmp.Pixel, height)
	for i := 0; i < int(height); i++ {
		body[i] = make([]bmp.Pixel, width)
	}
	for i := 0; i < int(height); i++ {
		for j := 0; j < int(width); j++ {
			body[i][j].B = uint8(arr[i][j*3])
			body[i][j].G = uint8(arr[i][j*3+1])
			body[i][j].R = uint8(arr[i][j*3+2])
		}
	}
	return
}

func encBmp(params ckks.Parameters, secretKey rlwe.SecretKey, body [][]bmp.Pixel) (pixelCipherText [][]*rlwe.Ciphertext) {
	parray := pixelToArray(body)
	pixelCipherText = make([][]*rlwe.Ciphertext, 3)
	height := len(parray)
	width := len(parray[0]) / 3
	for i := 0; i < 3; i++ {
		pixelCipherText[i] = make([]*rlwe.Ciphertext, len(parray))
	}
	var wg sync.WaitGroup
	wg.Add(3 * height)
	for i := 0; i < 3; i++ {
		for j := 0; j < height; j++ {
			go func(j int, i int) {
				encoder := ckks.NewEncoder(params)
				pixelPlainText := ckks.NewPlaintext(params, params.MaxLevel())
				encryptor := ckks.NewEncryptor(params, secretKey)
				encoder.Encode(parray[j][i*width:(i+1)*width], pixelPlainText, params.LogSlots())
				pixelCipherText[i][j] = encryptor.EncryptNew(pixelPlainText)
				wg.Done()
				// fmt.Println(i*width + j)
			}(j, i)
		}
	}
	// fmt.Println(count)
	wg.Wait()
	return
}

func encGrayScale(params ckks.Parameters, pixelCipherText [][]*rlwe.Ciphertext, publicKey rlwe.PublicKey, width int32, height int32, rKey *rlwe.RelinearizationKey) (grayScaleCipherText []*rlwe.Ciphertext) {
	grayScaleCipherText = make([]*rlwe.Ciphertext, height)
	var wg sync.WaitGroup
	wg.Add(int(height))
	for i := 0; i < int(height); i++ {
		go func(i int) {
			evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rKey})
			tempB := evaluator.MultByConstNew(pixelCipherText[0][i], 0.114)
			tempG := evaluator.MultByConstNew(pixelCipherText[1][i], 0.587)
			tempR := evaluator.MultByConstNew(pixelCipherText[2][i], 0.299)
			grayScaleCipherText[i] = evaluator.AddNew(tempB, tempG)
			grayScaleCipherText[i] = evaluator.AddNew(grayScaleCipherText[i], tempR)
			wg.Done()
		}(i)
	}
	wg.Wait()
	return
}

func main() {
	head, body := bmpRead("kingfisher.bmp")
	fmt.Printf("Resolution : %4d x%4d\n", head.Width, head.Height)

	start := time.Now().UnixMicro()
	params, err := ckks.NewParametersFromLiteral(ckks.PN14QP438)
	check(err)
	secretKey, publicKey := ckks.NewKeyGenerator(params).GenKeyPair()
	rKey := ckks.NewKeyGenerator(params).GenRelinearizationKey(secretKey, 1)
	end := time.Now().UnixMicro()

	fmt.Printf("Setup		: %8d μs\n", end-start)

	start = time.Now().UnixMicro()
	encbody := encBmp(params, *secretKey, body)
	// encbody := encBmpCon(params, *secretKey, body)
	end = time.Now().UnixMicro()

	fmt.Printf("Encryption	: %8d μs\n", end-start)

	start = time.Now().UnixMicro()
	grayBody := encGrayScale(params, encbody, *publicKey, head.Width, head.Height, rKey)
	end = time.Now().UnixMicro()

	fmt.Printf("Evaluation	: %8d μs\n", end-start)

	decbody := make([][]complex128, head.Height)

	start = time.Now().UnixMicro()
	var wg sync.WaitGroup
	wg.Add(len(grayBody))
	for i := 0; i < len(grayBody); i++ {
		go func(i int) {
			encoder := ckks.NewEncoder(params)
			decryptor := ckks.NewDecryptor(params, secretKey)
			decbody[i] = encoder.Decode(decryptor.DecryptNew(grayBody[i]), params.LogSlots())[:head.Width*3]
			wg.Done()
		}(i)
	}
	wg.Wait()
	end = time.Now().UnixMicro()
	fmt.Printf("Decryption	: %8d μs\n", end-start)

	after := make([][]float64, head.Height)
	for i := 0; i < int(head.Height); i++ {
		after[i] = make([]float64, 3*head.Width)
	}
	for i := 0; i < int(head.Height); i++ {
		for j := 0; j < int(3*head.Width); j++ {
			after[i][j] = real(decbody[i][j])
		}
	}

	bmpWrite("kingfisher2.bmp", head, arrayToPixel(after))
	grayscale(&body)
	bmpWrite("kingfisher3.bmp", head, body)
	return
}
