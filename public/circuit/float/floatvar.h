#pragma once

#include <libsnark/gadgetlib1/pb_variable.hpp>

#include "ecc/ecc.h"
#include "public.h"

namespace circuit::flt {
uint32_t E32 = 8, M32 = 23;
uint32_t E64 = 11, M64 = 52;
uint32_t E = E32, M = M32;

std::vector<Fr> Pow2((M<<1)+5);

struct float_var {
  libsnark::pb_variable<Fr> sign;
  libsnark::pb_variable<Fr> exponent;
  libsnark::pb_variable<Fr> mantissa;
  libsnark::pb_variable<Fr> abnormal;

  void assign(libsnark::protoboard<Fr> &pb, std::array<uint, 4> f) {
    pb.val(sign) = f[0];
    pb.val(exponent) = f[1];
    pb.val(mantissa) = f[2];
    pb.val(abnormal) = f[3];
  }

  void allocate(libsnark::protoboard<Fr> &pb){
    sign.allocate(pb);
    exponent.allocate(pb);
    mantissa.allocate(pb);
    abnormal.allocate(pb);
  }

  static std::array<uint, 4> NewF32(float v){
    uint32_t u = ConverFloatToUint(v);
    return NewF32(u);
  };

  static std::array<uint, 4> NewF32(uint v){
    return ComponentsOf32(v, E32, M32);
  }

  static float RecoverF32(std::array<uint, 4> v){
    return ValueOf(v, E32, M32);
  }

  static float ConverUintToFloat(uint32_t v){
    float f;
    std::memcpy(&f, &v, sizeof(f));
    return f;
  }

  static float ConverFloatToUint(float v){
    uint u;
    std::memcpy(&u, &v, sizeof(u));
    return u;
  }

  static std::array<uint, 4> ComponentsOf32(uint v, uint E, uint M){
    uint s = v >> (E + M);
    uint e = (v >> M) - (s << E);
    uint m = v - (s << (E + M)) - (e << M);
    uint a = 0;
  
    if(e == 0 && m == 0) { // v is zero
        s = 0;
    } else if(e == 0 && m != 0) { // v is subnormal
        for(e=M+1; m < (1 << M); m <<= 1, e--);
    } else if(e < (1<<E)-1) { // v is normals
        e += M;
        m += 1 << M;
    } else { // v is abnormal
        s = 0;
        m = 0;
        a = 1;
        e = 0;
    }
    return std::array<uint, 4>{s, e, m, a};
  }

  static float ValueOf(std::array<uint, 4> v, uint E, uint M)  {
    uint s = v[0];
    uint e = v[1];
    uint m = v[2];
    uint a = v[3];
    if (e == 0) {
      CHECK(m == 0 && s == 0, "");
      if(a == 0) return 0;
      else if(a == 1) return 0.0 / 0.0f;
      else CHECK(false, "");
    }else if (e <= M) {
      CHECK(m >= (1 << M) && m < (1 << (M+1)) && ((m>>(M+1-e))<<(M+1-e)) == m && a == 0, "");
      return ConverUintToFloat((s << (M + E)) + (m >> (M+1-e)));
    } else if(e < (1 << E) - 1 + M){
      e = e - M;
      CHECK(m >= (1 << M) && m < (1 << (M+1)) && a == 0, "");
      m = m - (1 << M);
      return ConverUintToFloat((s << (M + E)) + (e << M) + m);
    }else{
      CHECK(false, "");
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

inline bool TestFloatVar() {
  Tick tick(__FN__);
  const std::string path = std::string("/home/dj/work/gitwork/Float/data/f32/add_bak");
  std::vector<std::vector<uint32_t>> data;
  Read2DFile(path, data);
  for(size_t i=0; i<data.size(); i++){
    float f1 = float_var::ConverUintToFloat(data[i][0]);
    std::array<uint, 4> f32 = float_var::NewF32(data[i][0]);
    float f2 = float_var::RecoverF32(f32);
    if(!(((std::isnan(f1) || std::isinf(f1)) && std::isnan(f2)) || (f1 == f2))){
      CHECK(false, std::to_string(f1) + "\t" + std::to_string(f2));
    }
  }
  return true;
}

}