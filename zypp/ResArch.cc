/*---------------------------------------------------------------------\
|                          ____ _   __ __ ___                          |
|                         |__  / \ / / . \ . \                         |
|                           / / \ V /|  _/  _/                         |
|                          / /__ | | | | | |                           |
|                         /_____||_| |_| |_|                           |
|                                                                      |
\---------------------------------------------------------------------*/
/**
 \file	zypp/ResArch.cc

 \brief	.

*/
#include <iostream>

#include "zypp/ResArch.h"

using namespace std;

///////////////////////////////////////////////////////////////////
namespace zypp
{ /////////////////////////////////////////////////////////////////

  ///////////////////////////////////////////////////////////////////
  //
  //	METHOD NAME : ResArch::ResArch
  //	METHOD TYPE : Ctor
  //
  ResArch::ResArch()
  {}

  ///////////////////////////////////////////////////////////////////
  //
  //	METHOD NAME : ResArch::ResArch
  //	METHOD TYPE : Ctor
  //
  ResArch::ResArch( const std::string & rhs )
  : base::StringVal( rhs )
  {}

  ///////////////////////////////////////////////////////////////////
  //
  //	METHOD NAME : ResArch::ResArch
  //	METHOD TYPE : Ctor
  //
  ResArch::ResArch( const ResArch & rhs )
  : base::StringVal( rhs )
  {}

  ///////////////////////////////////////////////////////////////////
  //
  //	METHOD NAME : ResArch::~ResArch
  //	METHOD TYPE : Dtor
  //
  ResArch::~ResArch()
  {}

  /////////////////////////////////////////////////////////////////
} // namespace zypp
///////////////////////////////////////////////////////////////////
