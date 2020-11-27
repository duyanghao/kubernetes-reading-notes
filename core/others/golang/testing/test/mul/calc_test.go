package mul

import "testing"

type calcCase struct {
	Name     string
	A        int
	B        int
	Expected int
}

func createMulTestCase(t *testing.T, c *calcCase) {
	t.Helper()
	t.Run(c.Name, func(t *testing.T) {
		if ans := Mul(c.A, c.B); ans != c.Expected {
			t.Fatalf("%d * %d expected %d, but %d got",
				c.A, c.B, c.Expected, ans)
		}
	})
}

func TestMul(t *testing.T) {
	createMulTestCase(t, &calcCase{"subtest#1", 2, 3, 6})
	createMulTestCase(t, &calcCase{"subtest#2", 2, -3, -6})
	createMulTestCase(t, &calcCase{"subtest#3", 2, 0, 1}) // wrong case
}
