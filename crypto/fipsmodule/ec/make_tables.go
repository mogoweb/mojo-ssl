// Copyright (c) 2020, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//go:build ignore

package main

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
)

// 定义一条名为 “SM2p256v1” 的曲线
var SM2p256v1Params = &elliptic.CurveParams{Name: "SM2p256v1"}

func init() {
	// 素域 P
	SM2p256v1Params.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	// 系数 B
	SM2p256v1Params.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	// 基点 G 的 X 坐标
	SM2p256v1Params.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	// 基点 G 的 Y 坐标
	SM2p256v1Params.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	// 子群阶 N
	SM2p256v1Params.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	// 位大小
	SM2p256v1Params.BitSize = 256
}

// 返回曲线接口
func SM2p256v1() elliptic.Curve { return SM2p256v1Params }

func main() {
	if err := writeBuiltinCurves("builtin_curves.h"); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing builtin_curves.h: %s\n", err)
		os.Exit(1)
	}

	if err := writeP256NistzTable("p256-nistz-table.h"); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing p256-nistz-table.h: %s\n", err)
		os.Exit(1)
	}

	if err := writeP256Table("p256_table.h"); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing p256_table.h: %s\n", err)
		os.Exit(1)
	}
}

func writeBuiltinCurves(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := &columnWriter{w: f}

	const fileHeader = `/* Copyright (c) 2023, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// This file is generated by make_tables.go.
`
	if _, err := io.WriteString(w, fileHeader); err != nil {
		return err
	}
	// P-224 is the only curve where we have a non-Montgomery implementation.
	if err := writeCurveData(w, elliptic.P224(), true); err != nil {
		return err
	}
	if err := writeCurveData(w, elliptic.P256(), false); err != nil {
		return err
	}
	if err := writeCurveData(w, elliptic.P384(), false); err != nil {
		return err
	}
	if err := writeCurveData(w, elliptic.P521(), false); err != nil {
		return err
	}
	if err := writeCurveData(w, SM2p256v1(), false); err != nil {
		return err
  }
	return nil
}

func writeCurveData(w *columnWriter, curve elliptic.Curve, includeNonMontgomery bool) error {
	params := curve.Params()
	if _, err := fmt.Fprintf(w, "\n// %s\n", params.Name); err != nil {
		return err
	}

	cName := strings.Replace(params.Name, "-", "", -1)
	writeDecls := func(bits int) error {
		if err := writeDecl(w, curve, bits, fmt.Sprintf("k%sField", cName), params.P); err != nil {
			return err
		}
		if err := writeDecl(w, curve, bits, fmt.Sprintf("k%sOrder", cName), params.N); err != nil {
			return err
		}
		if includeNonMontgomery {
			if err := writeDecl(w, curve, bits, fmt.Sprintf("k%sB", cName), params.B); err != nil {
				return err
			}
			if err := writeDecl(w, curve, bits, fmt.Sprintf("k%sGX", cName), params.Gx); err != nil {
				return err
			}
			if err := writeDecl(w, curve, bits, fmt.Sprintf("k%sGY", cName), params.Gy); err != nil {
				return err
			}
		}
		if err := writeDecl(w, curve, bits, fmt.Sprintf("k%sFieldR", cName), montgomeryR(params.P, bits)); err != nil {
			return err
		}
		if err := writeDecl(w, curve, bits, fmt.Sprintf("k%sFieldRR", cName), montgomeryRR(params.P, bits)); err != nil {
			return err
		}
		if err := writeDecl(w, curve, bits, fmt.Sprintf("k%sOrderRR", cName), montgomeryRR(params.N, bits)); err != nil {
			return err
		}
		if err := writeDecl(w, curve, bits, fmt.Sprintf("k%sMontB", cName), toMontgomery(params.B, params.P, bits)); err != nil {
			return err
		}
		if err := writeDecl(w, curve, bits, fmt.Sprintf("k%sMontGX", cName), toMontgomery(params.Gx, params.P, bits)); err != nil {
			return err
		}
		if err := writeDecl(w, curve, bits, fmt.Sprintf("k%sMontGY", cName), toMontgomery(params.Gy, params.P, bits)); err != nil {
			return err
		}
		return nil
	}

	if _, err := fmt.Fprintf(w, "OPENSSL_UNUSED static const uint64_t k%sFieldN0 = 0x%016x;\n", cName, montgomeryN0(params.P)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "OPENSSL_UNUSED static const uint64_t k%sOrderN0 = 0x%016x;\n", cName, montgomeryN0(params.N)); err != nil {
		return err
	}

	if _, err := io.WriteString(w, "#if defined(OPENSSL_64_BIT)\n"); err != nil {
		return err
	}
	if err := writeDecls(64); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "#elif defined(OPENSSL_32_BIT)\n"); err != nil {
		return err
	}
	if err := writeDecls(32); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "#else\n#error \"unknown word size\"\n#endif\n"); err != nil {
		return err
	}
	return nil
}

func writeP256NistzTable(path string) error {
	curve := elliptic.P256()
	tables := make([][][2]*big.Int, 0, 37)
	for shift := 0; shift < 256; shift += 7 {
		row := makeMultiples(curve, 64, shift)
		tables = append(tables, row)
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := &columnWriter{w: f}

	const fileHeader = `/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2015, Intel Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

// This is the precomputed constant time access table for the code in
// p256-nistz.c, for the default generator. The table consists of 37
// subtables, each subtable contains 64 affine points. The affine points are
// encoded as eight uint64's, four for the x coordinate and four for the y.
// Both values are in little-endian order. There are 37 tables because a
// signed, 6-bit wNAF form of the scalar is used and ceil(256/(6 + 1)) = 37.
// Within each table there are 64 values because the 6-bit wNAF value can take
// 64 values, ignoring the sign bit, which is implemented by performing a
// negation of the affine point when required. We would like to align it to 2MB
// in order to increase the chances of using a large page but that appears to
// lead to invalid ELF files being produced.

// This file is generated by make_tables.go.

static const alignas(4096) PRECOMP256_ROW ecp_nistz256_precomputed[37] = `
	if _, err := io.WriteString(w, fileHeader); err != nil {
		return err
	}
	if err := writeTables(w, curve, tables, writeBNMont); err != nil {
		return err
	}
	if _, err := io.WriteString(w, ";\n"); err != nil {
		return err
	}

	return nil
}

func writeP256Table(path string) error {
	curve := elliptic.P256()
	tables := [][][2]*big.Int{
		makeComb(curve, 64, 4, 0),
		makeComb(curve, 64, 4, 32),
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := &columnWriter{w: f}

	const fileHeader = `/* Copyright (c) 2020, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// This file is generated by make_tables.go.

// Base point pre computation
// --------------------------
//
// Two different sorts of precomputed tables are used in the following code.
// Each contain various points on the curve, where each point is three field
// elements (x, y, z).
//
// For the base point table, z is usually 1 (0 for the point at infinity).
// This table has 2 * 16 elements, starting with the following:
// index | bits    | point
// ------+---------+------------------------------
//     0 | 0 0 0 0 | 0G
//     1 | 0 0 0 1 | 1G
//     2 | 0 0 1 0 | 2^64G
//     3 | 0 0 1 1 | (2^64 + 1)G
//     4 | 0 1 0 0 | 2^128G
//     5 | 0 1 0 1 | (2^128 + 1)G
//     6 | 0 1 1 0 | (2^128 + 2^64)G
//     7 | 0 1 1 1 | (2^128 + 2^64 + 1)G
//     8 | 1 0 0 0 | 2^192G
//     9 | 1 0 0 1 | (2^192 + 1)G
//    10 | 1 0 1 0 | (2^192 + 2^64)G
//    11 | 1 0 1 1 | (2^192 + 2^64 + 1)G
//    12 | 1 1 0 0 | (2^192 + 2^128)G
//    13 | 1 1 0 1 | (2^192 + 2^128 + 1)G
//    14 | 1 1 1 0 | (2^192 + 2^128 + 2^64)G
//    15 | 1 1 1 1 | (2^192 + 2^128 + 2^64 + 1)G
// followed by a copy of this with each element multiplied by 2^32.
//
// The reason for this is so that we can clock bits into four different
// locations when doing simple scalar multiplies against the base point,
// and then another four locations using the second 16 elements.
//
// Tables for other points have table[i] = iG for i in 0 .. 16.

// fiat_p256_g_pre_comp is the table of precomputed base points
#if defined(OPENSSL_64_BIT)
static const fiat_p256_felem fiat_p256_g_pre_comp[2][15][2] = `
	if _, err := io.WriteString(w, fileHeader); err != nil {
		return err
	}
	if err := writeTables(w, curve, tables, writeU64Mont); err != nil {
		return err
	}
	if _, err := io.WriteString(w, ";\n#else\nstatic const fiat_p256_felem fiat_p256_g_pre_comp[2][15][2] = "); err != nil {
		return err
	}
	if err := writeTables(w, curve, tables, writeU32Mont); err != nil {
		return err
	}
	if _, err := io.WriteString(w, ";\n#endif\n"); err != nil {
		return err
	}

	return nil
}

// makeMultiples returns a table of the first n multiples of 2^shift * G,
// starting from 1 * 2^shift * G.
func makeMultiples(curve elliptic.Curve, n, shift int) [][2]*big.Int {
	ret := make([][2]*big.Int, n)
	x, y := curve.Params().Gx, curve.Params().Gy
	for j := 0; j < shift; j++ {
		x, y = curve.Double(x, y)
	}
	ret[1-1] = [2]*big.Int{x, y}
	for i := 2; i <= n; i++ {
		if i&1 == 0 {
			x, y := curve.Double(ret[i/2-1][0], ret[i/2-1][1])
			ret[i-1] = [2]*big.Int{x, y}
		} else {
			x, y := curve.Add(ret[i-1-1][0], ret[i-1-1][1], ret[1-1][0], ret[1-1][1])
			ret[i-1] = [2]*big.Int{x, y}
		}
	}
	return ret
}

// makeComb returns a table of 2^size - 1 points. The i-1th entry is k*G.
// If i is represented in binary by b0*2^0 + b1*2^1 + ... bn*2^n, k is
// b0*2^(shift + 0*stride) + b1*2^(shift + 1*stride) + ... + bn*2^(shift + n*stride).
// The entry for i = 0 is omitted because it is always the point at infinity.
func makeComb(curve elliptic.Curve, stride, size, shift int) [][2]*big.Int {
	ret := make([][2]*big.Int, 1<<size-1)
	x, y := curve.Params().Gx, curve.Params().Gy
	for j := 0; j < shift; j++ {
		x, y = curve.Double(x, y)
	}
	ret[1<<0-1] = [2]*big.Int{x, y}
	for i := 1; i < size; i++ {
		// Entry 2^i is entry 2^(i-1) doubled stride times.
		x, y = ret[1<<(i-1)-1][0], ret[1<<(i-1)-1][1]
		for j := 0; j < stride; j++ {
			x, y = curve.Double(x, y)
		}
		ret[1<<i-1] = [2]*big.Int{x, y}
		// The remaining entries with MSB 2^i are computed by adding entry 2^i
		// to the corresponding previous entry.
		for j := 1; j < 1<<i; j++ {
			x, y = curve.Add(ret[1<<i-1][0], ret[1<<i-1][1], ret[j-1][0], ret[j-1][1])
			ret[1<<i+j-1] = [2]*big.Int{x, y}
		}
	}
	return ret
}

func montgomeryR(p *big.Int, wordSize int) *big.Int {
	// R is the bit width of p, rounded up to word size.
	rounded := wordSize * ((p.BitLen() + wordSize - 1) / wordSize)
	R := new(big.Int).SetInt64(1)
	R.Lsh(R, uint(rounded))
	R.Mod(R, p)
	return R
}

func montgomeryRR(p *big.Int, wordSize int) *big.Int {
	R := montgomeryR(p, wordSize)
	R.Mul(R, R)
	R.Mod(R, p)
	return R
}

func montgomeryN0(p *big.Int) uint64 {
	two64 := new(big.Int)
	two64 = two64.SetBit(two64, 64, 1)
	n0 := new(big.Int).Neg(p)
	n0 = n0.ModInverse(n0, two64)
	if !n0.IsUint64() {
		panic("n0 should fit in uint64")
	}
	return n0.Uint64()
}

// toMontgomery returns n×R mod p, where R is the Montgomery factor.
func toMontgomery(n, p *big.Int, wordSize int) *big.Int {
	ret := montgomeryR(p, wordSize)
	ret.Mul(ret, n)
	ret.Mod(ret, p)
	return ret
}

func bigIntToU64s(curve elliptic.Curve, n *big.Int) []uint64 {
	words := (curve.Params().BitSize + 63) / 64
	ret := make([]uint64, words)
	bytes := n.Bytes()
	for i, b := range bytes {
		i = len(bytes) - i - 1
		ret[i/8] |= uint64(b) << (8 * (i % 8))
	}
	return ret
}

func bigIntToU32s(curve elliptic.Curve, n *big.Int) []uint32 {
	words := (curve.Params().BitSize + 31) / 32
	ret := make([]uint32, words)
	bytes := n.Bytes()
	for i, b := range bytes {
		i = len(bytes) - i - 1
		ret[i/4] |= uint32(b) << (8 * (i % 4))
	}
	return ret
}

// A columnWriter is an io.Writer that tracks the number of columns in the
// current line.
type columnWriter struct {
	w      io.Writer
	column int
}

func (c *columnWriter) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	idx := bytes.LastIndexByte(p[:n], '\n')
	if idx < 0 {
		c.column += n
	} else {
		c.column = n - idx - 1
	}
	return
}

func writeIndent(w io.Writer, indent int) error {
	for i := 0; i < indent; i++ {
		if _, err := io.WriteString(w, " "); err != nil {
			return err
		}
	}
	return nil
}

func writeWordsBraced[Word any](w *columnWriter, words []Word, format func(Word) string) error {
	if _, err := io.WriteString(w, "{"); err != nil {
		return err
	}
	if err := writeWords(w, words, format); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "}"); err != nil {
		return err
	}
	return nil
}

func writeWords[Word any](w *columnWriter, words []Word, format func(Word) string) error {
	indent := w.column
	for i, word := range words {
		str := format(word)
		if i > 0 {
			if w.column+1+len(str) > 80 {
				if _, err := io.WriteString(w, ",\n"); err != nil {
					return err
				}
				if err := writeIndent(w, indent); err != nil {
					return err
				}
			} else {
				if _, err := io.WriteString(w, ", "); err != nil {
					return err
				}
			}
		}
		if _, err := io.WriteString(w, str); err != nil {
			return err
		}
	}
	return nil
}

func writeDecl(w *columnWriter, curve elliptic.Curve, bits int, decl string, n *big.Int) error {
	if _, err := fmt.Fprintf(w, "OPENSSL_UNUSED static const uint%d_t %s[] = {\n    ", bits, decl); err != nil {
		return err
	}
	if bits == 32 {
		if err := writeWords(w, bigIntToU32s(curve, n), formatU32); err != nil {
			return err
		}
	} else if bits == 64 {
		if err := writeWords(w, bigIntToU64s(curve, n), formatU64); err != nil {
			return err
		}
	} else {
		panic("unknown bit count")
	}
	if _, err := fmt.Fprintf(w, "};\n"); err != nil {
		return err
	}
	return nil
}

func formatBN(word uint64) string {
	return fmt.Sprintf("TOBN(0x%08x, 0x%08x)", uint32(word>>32), uint32(word))
}

func formatU64(word uint64) string {
	return fmt.Sprintf("0x%016x", word)
}

func formatU32(word uint32) string {
	return fmt.Sprintf("0x%08x", word)
}

func writeBNMont(w *columnWriter, curve elliptic.Curve, n *big.Int) error {
	n32 := toMontgomery(n, curve.Params().P, 32)
	n64 := toMontgomery(n, curve.Params().P, 64)
	if n32.Cmp(n64) != 0 {
		panic(fmt.Sprintf("Montgomery form for %s is inconsistent between 32-bit and 64-bit", curve.Params().Name))
	}
	return writeWordsBraced(w, bigIntToU64s(curve, n64), formatBN)
}

func writeU64Mont(w *columnWriter, curve elliptic.Curve, n *big.Int) error {
	n = toMontgomery(n, curve.Params().P, 64)
	return writeWordsBraced(w, bigIntToU64s(curve, n), formatU64)
}

func writeU32Mont(w *columnWriter, curve elliptic.Curve, n *big.Int) error {
	n = toMontgomery(n, curve.Params().P, 32)
	return writeWordsBraced(w, bigIntToU32s(curve, n), formatU32)
}

type writeBigIntFunc func(w *columnWriter, curve elliptic.Curve, n *big.Int) error

func writeTable(w *columnWriter, curve elliptic.Curve, table [][2]*big.Int, writeBigInt writeBigIntFunc) error {
	if _, err := io.WriteString(w, "{"); err != nil {
		return err
	}
	indent := w.column
	for i, point := range table {
		if i != 0 {
			if _, err := io.WriteString(w, ",\n"); err != nil {
				return err
			}
			if err := writeIndent(w, indent); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "{"); err != nil {
			return err
		}
		if err := writeBigInt(w, curve, point[0]); err != nil {
			return err
		}
		if _, err := io.WriteString(w, ",\n"); err != nil {
			return err
		}
		if err := writeIndent(w, indent+1); err != nil {
			return err
		}
		if err := writeBigInt(w, curve, point[1]); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "}"); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "}"); err != nil {
		return err
	}
	return nil
}

func writeTables(w *columnWriter, curve elliptic.Curve, tables [][][2]*big.Int, writeBigInt writeBigIntFunc) error {
	if _, err := io.WriteString(w, "{\n    "); err != nil {
		return err
	}
	indent := w.column
	for i, table := range tables {
		if i != 0 {
			if _, err := io.WriteString(w, ",\n"); err != nil {
				return err
			}
			if err := writeIndent(w, indent); err != nil {
				return err
			}
		}
		if err := writeTable(w, curve, table, writeBigInt); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "}"); err != nil {
		return err
	}
	return nil
}
