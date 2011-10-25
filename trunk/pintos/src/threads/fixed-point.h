#ifndef FIXED_POINT_H_
#define FIXED_POINT_H_

#include <stdint.h>

#define Q 14
#define F (1 << Q)

typedef int fixedpoint;

fixedpoint convert_int_to_fixedpoint (int n);
int convert_fixedpoint_to_int (fixedpoint fixedpoint);

fixedpoint fixedpoint_add (fixedpoint x, fixedpoint y);
fixedpoint fixedpoint_add_int (fixedpoint x, int n);
fixedpoint fixedpoint_subtract (fixedpoint x, fixedpoint y);
fixedpoint fixedpoint_subtract_int (fixedpoint x, int n);
fixedpoint fixedpoint_multiply (fixedpoint x, fixedpoint y);
fixedpoint fixedpoint_multiply_int (fixedpoint x, int n);
fixedpoint fixedpoint_divide (fixedpoint x, fixedpoint y);
fixedpoint fixedpoint_divide_int (fixedpoint x, int n);

#endif
