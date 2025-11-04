package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils"
	"math"
	"math/rand"
	"os"
	"strconv"
	"time"
)

var flagShort = flag.Bool("short", false, "run the example with a smaller and insecure ring degree.")

func main() {

	flag.Parse()

	LogN := 13

	if *flagShort {
		LogN -= 3
	}

	// ===================================
	// 1.Instantiating the ckks.Parameters
	// ===================================

	var err error
	var params ckks.Parameters
	if params, err = ckks.NewParametersFromLiteral(
		ckks.ParametersLiteral{
			LogN: LogN, // Log2 of the ring degree
			LogQ: []int{55, 40, 40, 40, 40, 40, 40, 40, 40, 40,
				40, 40, 40, 40, 40, 40, 40}, // Log2 of the ciphertext prime moduli
			LogP:            []int{61, 61, 61},    // Log2 of the key-switch auxiliary prime moduli
			LogDefaultScale: 40,                   // Log2 of the scale
			Xs:              ring.Ternary{H: 192}, // The default log2 of the scaling factor
		}); err != nil {
		panic(err)
	}

	//prec := params.EncodingPrecision()
	Slots := params.MaxSlots()

	// ==================================
	// 2. BOOTSTRAPPING PARAMETERSLITERAL
	// ==================================
	btpParametersLit := bootstrapping.ParametersLiteral{

		LogN: utils.Pointy(LogN),

		LogP: []int{61, 61, 61, 61},

		Xs: params.Xs(),
	}

	btpParams, err := bootstrapping.NewParametersFromLiteral(params, btpParametersLit)
	if err != nil {
		panic(err)
	}

	if *flagShort {
		// Corrects the message ratio Q0/|m(X)| to take into account the smaller number of slots and keep the same precision
		btpParams.Mod1ParametersLiteral.LogMessageRatio += 16 - params.LogN()
	}

	// ================
	// 3.Key Generation
	// ================

	// Key Generator
	fmt.Println()
	fmt.Println("1. Generating ckks keys...")
	kgen := rlwe.NewKeyGenerator(params)
	//fmt.Printf("LogQP <= 438: %v\n", params.LogQP())

	// Secret Key
	sk := kgen.GenSecretKeyNew()

	// Public Key
	pk := kgen.GenPublicKeyNew(sk)

	// Relinearlization Key
	rlk := kgen.GenRelinearizationKeyNew(sk)

	// Evaluation Key
	evk := rlwe.NewMemEvaluationKeySet(rlk)
	fmt.Println("Done")

	// Bootstrapping evaluation key
	fmt.Println()
	fmt.Println("2. Generating bootstrapping evaluation keys...")
	btpEvk, _, err := btpParams.GenEvaluationKeys(sk)
	if err != nil {
		panic(err)
	}
	fmt.Println("Done")

	// ================
	// 4. BOOTSTRAPPING
	// ================

	// Instantiates the bootstrapper
	var btpEval *bootstrapping.Evaluator
	if btpEval, err = bootstrapping.NewEvaluator(btpParams, btpEvk); err != nil {
		panic(err)
	}

	// Encoder
	ecd := ckks.NewEncoder(ckks.Parameters(params))
	// Encryptor
	enc := rlwe.NewEncryptor(params, pk)
	dec := rlwe.NewDecryptor(params, sk)
	eval := ckks.NewEvaluator(params, evk)

	//file, err := os.Open("data/Yale_left.csv")
	//file, err := os.Open("data/Yale_right.csv")
	//file, err := os.Open("data/Air_left.csv")
	//file, err := os.Open("data/Air_right.csv")
	//file, err := os.Open("data/wine_left.csv")
	file, err := os.Open("data/wine_right.csv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		panic(err)
	}
	//
	var A [][]float64
	for _, row := range records {
		var floatRow []float64
		for _, val := range row {
			f, err := strconv.ParseFloat(val, 64)
			if err != nil {
				panic(err)
			}
			floatRow = append(floatRow, f)
		}
		A = append(A, floatRow)
	}

	//A := [][]float64{
	//	{1.0, 2.0, 3.0, 4.0},
	//	{4.0, 1.0, 2.0, 3.0},
	//	{3.0, 4.0, 1.0, 2.0},
	//	{2.0, 3.0, 4.0, 1.0},
	//}

	//设置随机种子
	//r := rand.New(rand.NewSource(50))

	// 矩阵维度
	//n := 4

	// 创建一个二维切片
	//A := make([][]float64, n)
	//for i := 0; i < n; i++ {
	//	A[i] = make([]float64, n) // 每行初始化长度为 n
	//	for j := 0; j < n; j++ {
	//		randomValue := r.Float64() * 10 // 生成 0 到 99 的随机整数
	//		A[i][j] = float64(int(randomValue + 0.5))
	//	}
	//}

	// 输出随机二维数组
	//fmt.Println("随机生成的二维整型数组:")
	//for _, row := range A {
	//	fmt.Println(row)
	//}

	// 获取矩阵的维度 n
	n := len(A)

	// 创建一个切片用于存储展开后的结果
	var rowA []float64

	// 按行展开二维数组
	for _, row := range A {
		rowA = append(rowA, row...)
	}
	//fmt.Println(rowA)

	ptRowA := ckks.NewPlaintext(params, params.MaxLevel())
	if err = ecd.Encode(rowA, ptRowA); err != nil {
		panic(err)
	}
	ctRowA, err := enc.EncryptNew(ptRowA)
	if err != nil {
		panic(err)
	}

	//lt, ltEval := LinearTrans(A, Slots, n, ctVec, params, ecd, eval, kgen, rlk, sk)

	// Homomorphic matrix x vector
	//ctLintransVec := HomomoMatMutiVec(lt, ltEval, ctVec, eval)

	max_iter := 4 // Number of Powermethod iteration
	batch := 1
	//d := 5 // Number of Newton iteration
	d := 6
	evalInnsum := eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(batch, n), sk)...))

	a := []float64{-0.00013651433183402268}
	b := []float64{0.13651433183402267}

	f1 := []float64{0.5}
	f2 := []float64{1.5}

	pta := ckks.NewPlaintext(params, params.MaxLevel())
	ptb := ckks.NewPlaintext(params, params.MaxLevel())

	ptf1 := ckks.NewPlaintext(params, params.MaxLevel())
	ptf2 := ckks.NewPlaintext(params, params.MaxLevel())

	if err = ecd.Encode(a, pta); err != nil {
		panic(err)
	}

	if err = ecd.Encode(b, ptb); err != nil {
		panic(err)
	}

	if err = ecd.Encode(f1, ptf1); err != nil {
		panic(err)
	}

	if err = ecd.Encode(f2, ptf2); err != nil {
		panic(err)
	}

	// 0向量加密
	//vec0 := make([]float64, Slots)
	//ptVec0 := ckks.NewPlaintext(params, params.MaxLevel())
	//if err = ecd.Encode(vec0, ptVec0); err != nil {
	//	panic(err)
	//}
	//ctVec0, err := enc.EncryptNew(ptVec0)
	//if err != nil {
	//	panic(err)
	//}

	rot := -1
	galElsRot := []uint64{
		// The galois element for the cyclic rotations by 1 positions to the right.
		params.GaloisElement(rot)}
	rotEval := eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(galElsRot, sk)...))

	rot1 := -n
	galElsRot1 := []uint64{
		params.GaloisElement(rot1)}
	rotEval1 := eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(galElsRot1, sk)...))

	//start := time.Now()
	//ctEigenVec, ctEigenVal := HomomoPowerMethod(evalInnsum, lt, ltEval,
	//	ctVec, eval, max_iter, batch, n, ptf1, ptf2, cty0, cty01, btpEval, d, ctVec0, LogN, rotEval, rotEval1, rot, rot1)
	//elapsed := time.Since(start)
	//fmt.Println()
	//fmt.Printf("The times of homomoPowerMethod: %v\n", elapsed)
	//
	//eigenVec := dec.DecryptNew(ctEigenVec)
	//eigenVecList := make([]float64, Slots)
	//if err = ecd.Decode(eigenVec, eigenVecList); err != nil {
	//	panic(err)
	//}
	//
	//fmt.Printf("%2sEigenVector: ", "")
	//for i := 0; i < 5; i++ {
	//	fmt.Printf("%20.15f ", eigenVecList[i])
	//}
	//fmt.Printf("...\n")
	//
	//eigenVal := dec.DecryptNew(ctEigenVal)
	//ctEigenValList := make([]float64, Slots)
	//if err = ecd.Decode(eigenVal, ctEigenValList); err != nil {
	//	panic(err)
	//}
	//
	//fmt.Printf("%2sEigenValue: ", "")
	//for i := 0; i < 5; i++ {
	//	fmt.Printf("%20.15f ", ctEigenValList[i])
	//}
	//fmt.Printf("...\n")
	//
	ptVector := ckks.NewPlaintext(params, params.MaxLevel())
	//
	//vec00 := make([]float64, Slots)
	//ptVec00 := ckks.NewPlaintext(params, params.MaxLevel())
	//if err = ecd.Encode(vec00, ptVec00); err != nil {
	//	panic(err)
	//}
	//ctVec00, err := enc.EncryptNew(ptVec00)
	//if err != nil {
	//	panic(err)
	//}
	//
	//vec000 := make([]float64, Slots)
	//ptVec000 := ckks.NewPlaintext(params, params.MaxLevel())
	//if err = ecd.Encode(vec000, ptVec000); err != nil {
	//	panic(err)
	//}
	//ctVec000, err := enc.EncryptNew(ptVec00)
	//if err != nil {
	//	panic(err)
	//}
	//
	//// 执行Eigen shift算法
	//ctShiftMat := HomomoEigenShift(ctRowA, ctEigenVec, ctEigenVal, rotEval, rot, ptVector, eval, n, evalInnsum, batch, params, kgen, rlk, sk, ctVec0, ctVec00, ctVec000, ecd)
	//
	//ptShiftMat := dec.DecryptNew(ctShiftMat)
	//shiftMatVec := make([]float64, Slots)
	//if err = ecd.Decode(ptShiftMat, shiftMatVec); err != nil {
	//	panic(err)
	//}
	//
	//fmt.Printf("%vshift matrix: ", "")
	//for i := 0; i < 16; i++ {
	//	fmt.Printf("%20.15f ", shiftMatVec[i])
	//}
	//fmt.Printf("...\n")
	//
	//// 创建二维数组
	//shiftMat := make([][]float64, n)
	//for i := 0; i < n; i++ {
	//	shiftMat[i] = make([]float64, n)
	//}
	//
	//// 填充二维数组
	//nPow := math.Pow(float64(n), 2)
	//for i := 0; i < int(nPow); i++ {
	//	row := i / n
	//	col := i % n
	//	shiftMat[row][col] = shiftMatVec[i]
	//}
	//fmt.Println("转换后的二维数组:")
	//for _, row := range shiftMat {
	//	fmt.Println(row)
	//}

	lE := 4
	singularVec := make([][]float64, n)
	singularVal := make([]float64, n)
	start := time.Now()
	for i := 0; i < lE; i++ {
		fmt.Println()
		fmt.Printf("第%d次循环...", i+1)

		// Generate random vector
		r := rand.New(rand.NewSource(int64(i + 5)))
		arr := make([]float64, n)
		for i := 0; i < n; i++ {
			arr[i] = 2*r.Float64() - 1
		}
		vec := arr
		//vec := []float64{1.0, 0.0, 3.0, 2.0}
		fmt.Println()
		fmt.Println("生成的随机向量:", vec)

		ptVec := ckks.NewPlaintext(params, params.MaxLevel())
		if err = ecd.Encode(vec, ptVec); err != nil {
			panic(err)
		}
		ctVec, err := enc.EncryptNew(ptVec)
		if err != nil {
			panic(err)
		}

		// 0向量加密
		vec0 := make([]float64, Slots)
		ptVec0 := ckks.NewPlaintext(params, params.MaxLevel())
		if err = ecd.Encode(vec0, ptVec0); err != nil {
			panic(err)
		}
		ctVec0, err := enc.EncryptNew(ptVec0)
		if err != nil {
			panic(err)
		}
		vec00 := make([]float64, Slots)
		ptVec00 := ckks.NewPlaintext(params, params.MaxLevel())
		if err = ecd.Encode(vec00, ptVec00); err != nil {
			panic(err)
		}
		ctVec00, err := enc.EncryptNew(ptVec00)
		if err != nil {
			panic(err)
		}

		vec000 := make([]float64, Slots)
		ptVec000 := ckks.NewPlaintext(params, params.MaxLevel())
		if err = ecd.Encode(vec000, ptVec000); err != nil {
			panic(err)
		}
		ctVec000, err := enc.EncryptNew(ptVec00)
		if err != nil {
			panic(err)
		}

		lt, ltEval := LinearTrans(A, Slots, n, ctVec, params, ecd, eval, kgen, rlk, sk)

		ctLintransVec, ctEigenVec, ctEigenVal := HomomoPowerMethod(evalInnsum, lt, ltEval,
			ctVec, eval, dec, ecd, Slots, max_iter, batch, n, ptf1, ptf2, pta, ptb, btpEval, d, ctVec0, LogN, rotEval, rotEval1, rot, rot1)

		ctShiftMat := HomomoEigenShift(ctRowA, ctEigenVec, ctEigenVal, rotEval, rot, ptVector, eval, n, evalInnsum, batch, params, kgen, rlk, sk, ctVec0, ctVec00, ctVec000, ecd)

		ptShiftMat := dec.DecryptNew(ctShiftMat)
		shiftMatVec := make([]float64, Slots)
		if err = ecd.Decode(ptShiftMat, shiftMatVec); err != nil {
			panic(err)
		}

		shiftMat := make([][]float64, n)
		for i := 0; i < n; i++ {
			shiftMat[i] = make([]float64, n)
		}

		// 填充二维数组
		nPow := math.Pow(float64(n), 2)
		for i := 0; i < int(nPow); i++ {
			row := i / n
			col := i % n
			shiftMat[row][col] = shiftMatVec[i]
		}

		A = shiftMat
		ctRowA = ctShiftMat

		LintransVec := dec.DecryptNew(ctLintransVec)
		LintransVecList := make([]float64, Slots)
		if err = ecd.Decode(LintransVec, LintransVecList); err != nil {
			panic(err)
		}

		fmt.Printf("%2sLintransVec: ", "")
		for i := 0; i < 5; i++ {
			fmt.Printf("%20.15f ", LintransVecList[i])
		}
		fmt.Printf("...\n")

		eigenVec := dec.DecryptNew(ctEigenVec)
		eigenVecList := make([]float64, Slots)
		if err = ecd.Decode(eigenVec, eigenVecList); err != nil {
			panic(err)
		}

		fmt.Printf("%2sEigenVector: ", "")
		for i := 0; i < 5; i++ {
			fmt.Printf("%20.15f ", eigenVecList[i])
		}
		fmt.Printf("...\n")

		// 将所有的特征向量放到数组中
		singularVec[i] = eigenVecList[:n]

		fmt.Printf("%2sSingularVec: ", "")
		fmt.Println(singularVec)

		eigenVal := dec.DecryptNew(ctEigenVal)
		eigenValList := make([]float64, Slots)
		if err = ecd.Decode(eigenVal, eigenValList); err != nil {
			panic(err)
		}

		fmt.Printf("%2sEigenValue: ", "")
		for i := 0; i < 5; i++ {
			fmt.Printf("%20.15f ", eigenValList[i])
		}
		fmt.Printf("...\n")

		//将所有的特征值放到向量中
		singularVal[i] = eigenValList[0]
		fmt.Printf("%2sSingularVal: ", "")
		fmt.Println(singularVal)
	}
	elapsed := time.Since(start)
	fmt.Println()
	fmt.Printf("The times of SVD: %v\n", elapsed)

	// 创建CSV文件
	file, err = os.Create("result/output.csv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入数据
	for i := 0; i < lE; i++ {
		var row []string
		for j := 0; j < len(singularVec[i]); j++ {
			row = append(row, strconv.FormatFloat(singularVec[i][j], 'f', 20, 64))
		}
		// 加上向量值
		row = append(row, strconv.FormatFloat(singularVal[i], 'f', 20, 64))
		writer.Write(row)
	}

	fmt.Println("CSV 文件生成成功")
}
