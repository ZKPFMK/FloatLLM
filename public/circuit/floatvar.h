#pragma once

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>

#include "ecc/ecc.h"
#include "./public.h"

namespace circuit::flt {
uint32_t E32 = 8, M32 = 23;
uint32_t E64 = 11, M64 = 52;
uint32_t E = E32, M = M32;

struct float_var {
  libsnark::pb_variable<Fr> sign;
  libsnark::pb_variable<Fr> exponent;
  libsnark::pb_variable<Fr> mantissa;

  void allocate(libsnark::protoboard<Fr> &pb, const std::string &annotation=""){
    sign.allocate(pb, annotation);
    exponent.allocate(pb, annotation);
    mantissa.allocate(pb, annotation);
  }

  static std::array<uint, 3> NewF32(float v){
    uint32_t u = ConverFloatToUint(v);
    return NewF32(u);
  };

  static std::array<uint, 3> NewF32(uint32_t v){
    return ComponentsOf(v, E32, M32);
  }

  static float RecoverF32(std::array<uint, 3> v){
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

  static std::array<uint, 3> ComponentsOf(uint32_t v, uint32_t E, uint32_t M){
    uint32_t s = v >> (E + M);
    uint32_t e = (v >> M) - (s << E);
    uint32_t m = v - (s << (E + M)) - (e << M);

    if(e == 0 && m == 0) { // v is zero
        s = 0;
    } else if(e == 0 && m != 0) { // v is subnormal
        for(; m < (1 << M); m <<= 1, e++);
    } else if(e < (1<<E)-1) {
        e += M;
        m += 1 << M;
    } else {
        s = 0;
        m = 0;
        e += M;
    }
    return std::array<uint, 3>{s, e, m};
  }

  static float ValueOf(std::array<uint, 3> v, uint32_t E, uint32_t M)  {
    uint32_t s = v[0];
    uint32_t e = v[1];
    uint32_t m = v[2];
    if (e == 0) {
      if (m != 0) {
          CHECK(false, "");
        }
        return 0;
    }else if (e <= M) {
      if ((m>>e)<<e != m) {
        CHECK(false, "");
      }
      return ConverUintToFloat((s << (M + E)) + (m >> e));
    } else {
      e = e - M;
      if(m != 0){
        if(m < (1 << M)){
          CHECK(false, "");
        }else{
          m = m - (1 << M);
        }
      }else{
        if(e != (1 << E)-1){
          CHECK(false, "");
        }
        s = 0;
      }
      return ConverUintToFloat((s << (M + E)) + (e << M) + m);
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
  const std::string path = std::string("/home/dj/program/gitwork/zk-Location/data/f32/sqrt_bak");
  std::vector<std::vector<uint32_t>> data;
  Read2DFile(path, data);

  for(size_t i=0; i<data.size(); i++){
    float f1 = float_var::ConverUintToFloat(data[i][0]);
    std::array<uint, 3> f32 = float_var::NewF32(data[i][0]);
    float f2 = float_var::RecoverF32(f32);
    if(!(((std::isnan(f1) || std::isinf(f1)) && std::isinf(f2)) || (f1 == f2))){
      CHECK(false, std::to_string(f1) + "\t" + std::to_string(f2));
    }
  }
  return true;
}

}