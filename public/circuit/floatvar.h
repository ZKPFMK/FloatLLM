#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>

#include "ecc/ecc.h"
#include "./public.h"

namespace circuit::flt {
uint8_t E32 = 8, E64 = 11;
uint8_t M32 = 23, M64 = 52;

struct FloatVar {
    libsnark::pb_variable<Fr> sign;
    libsnark::pb_variable<Fr> exponent;
    libsnark::pb_variable<Fr> mantissa;

    static float NewF32(FloatVar v){
        
    }

    static std::array<Fr, 3> NewF32(float v){
        uint32_t bits;
        std::memcpy(&bits, &v, sizeof(float));
        return NewF32(bits);
    };

    static std::array<Fr, 3> NewF32(uint32_t v){
        ComponentsOf(v, E32, M32);
    }

    static std::array<Fr, 3> ComponentsOf(uint32_t v, uint8_t E, uint8_t M){
        uint8_t s = v >> (E + M);
        uint8_t e = (v >> M) - (s << E);
        uint32_t m = v - (s << (E + M)) - (e << M);
        if(e == 0 && m == 0) { // v is zero
            s = 0;
        } else if(e == 0 && m != 0) { // v is subnormal
            for(; m < (1 << M); m <<= 1) e++;
        } else if(e < (1<<E)-1) {
            e += M;
            m += 1 << M;
        } else {
            s = 0;
            m = 0;
            e += M;
        }
        return std::array<Fr, 3>{s, e, m};
    }

    static float ValueOf(std::array<uint, 3> v, uint8_t E, uint8_t M)  {
        uint8_t s = v[0];
        uint8_t e = new(big.Int).Add(components[1], big.NewInt(int64((1<<(E-1))-1+M))).Uint64()
        uint8_t m = v[2];
        if e <= M {
            if is_abnormal || (e == 0) != (m == 0) {
                panic("")
            }
            delta := M + 1 - e
            if (m>>delta)<<delta != m {
                panic("")
            }
            return (s << (M + E)) + (m >> delta)
        } else {
            e = e - M
            if (e == (1<<E)-1) != is_abnormal {
                panic("")
            }
            if is_abnormal && m == 0 {
                m = 1
            } else {
                m = m - (1 << M)
            }
            return (s << (M + E)) + (e << M) + m
        }
    }
};

void Read1DFile(std::string const& path, std::vector<uint32_t> & data){
  std::ifstream fin(path);
  if (!fin.is_open()) {
    std::cerr << "failed to open file: " << path << "\n";
    return;
  }
  std::string line;
  while (std::getline(fin, line)) {
    uint64_t val = std::stoull(line, nullptr, 16);
    data.push_back(val);
  }
}

void Read2DFile(std::string const& path, std::vector< std::vector<uint32_t>> & data){
  std::ifstream fin(path);
  if (!fin.is_open()) {
    std::cerr << "failed to open file: " << path << "\n";
    return;
  }
  std::string line;
  while (std::getline(fin, line)) {
    std::string token;
    std::istringstream iss(line);
    std::vector<uint32_t> values;
    while (iss >> token) {
      uint64_t val = std::stoull(token, nullptr, 16);
      values.push_back(val);
    }
    data.push_back(values);
  }
}

inline bool FloatVarTest() {
  Tick tick(__FN__);
  const std::string path = std::string("/home/dj/work/gitwork/Float/data/f32/sqrt");
  std::vector<std::vector<uint32_t>> data;
  Read2DFile(path, data);

  return true;
}

}