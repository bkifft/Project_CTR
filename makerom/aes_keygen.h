#pragma once
#include <stdint.h>

/*
	AES Key generator for the Nintendo (Handheld) Consoles

	BYO keygen constants, and input >>> parameters

	key = ((x >>> x_shift) ^ (y >>> y_shift)) + keygen_constant
*/

void n_aes_keygen(const uint8_t *x, uint8_t x_shift, const uint8_t *y, uint8_t y_shift, const uint8_t *keygen_constant, uint8_t *key);
