/*---------------------------------------------------------------------\
|                          ____ _   __ __ ___                          |
|                         |__  / \ / / . \ . \                         |
|                           / / \ V /|  _/  _/                         |
|                          / /__ | | | | | |                           |
|                         /_____||_| |_| |_|                           |
|                                                                      |
\---------------------------------------------------------------------*/
/**
 \file	zypp/ResKind.cc

 \brief	.

*/
#include <iostream>

#include "zypp/ResKind.h"

using namespace std;

///////////////////////////////////////////////////////////////////
namespace zypp
{ /////////////////////////////////////////////////////////////////

  ///////////////////////////////////////////////////////////////////
  //
  //	METHOD NAME : ResKind::ResKind
  //	METHOD TYPE : Ctor
  //
  ResKind::ResKind()
  {}

  ///////////////////////////////////////////////////////////////////
  //
  //	METHOD NAME : ResKind::ResKind
  //	METHOD TYPE : Ctor
  //
  ResKind::ResKind( const std::string & rhs )
  : base::StringVal( rhs )
  {}

  ///////////////////////////////////////////////////////////////////
  //
  //	METHOD NAME : ResKind::ResKind
  //	METHOD TYPE : Ctor
  //
  ResKind::ResKind( const ResKind & rhs )
  : base::StringVal( rhs )
  {}

  ///////////////////////////////////////////////////////////////////
  //
  //	METHOD NAME : ResKind::~ResKind
  //	METHOD TYPE : Dtor
  //
  ResKind::~ResKind()
  {}

  /////////////////////////////////////////////////////////////////
} // namespace zypp
///////////////////////////////////////////////////////////////////
