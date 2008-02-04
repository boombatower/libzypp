/*---------------------------------------------------------------------\
|                          ____ _   __ __ ___                          |
|                         |__  / \ / / . \ . \                         |
|                           / / \ V /|  _/  _/                         |
|                          / /__ | | | | | |                           |
|                         /_____||_| |_| |_|                           |
|                                                                      |
\---------------------------------------------------------------------*/
/** \file	zypp/ResKind.cc
 *
*/
#include <iostream>

#include "zypp/base/String.h"

#include "zypp/ResKind.h"
#include "zypp/ResTraits.h"

using std::endl;

///////////////////////////////////////////////////////////////////
namespace zypp
{ /////////////////////////////////////////////////////////////////

  const ResKind ResKind::atom      ( "atom" );
  const ResKind ResKind::message   ( "message" );
  const ResKind ResKind::package   ( "package" );
  const ResKind ResKind::patch     ( "patch" );
  const ResKind ResKind::pattern   ( "pattern" );
  const ResKind ResKind::product   ( "product" );
  const ResKind ResKind::script    ( "script" );
  const ResKind ResKind::srcpackage( "srcpackage" );

  template<>
    const ResKind ResTraits<Atom>      ::kind( ResKind::atom );
  template<>
    const ResKind ResTraits<Message>   ::kind( ResKind::message );
  template<>
    const ResKind ResTraits<Package>   ::kind( ResKind::package );
  template<>
    const ResKind ResTraits<Patch>     ::kind( ResKind::patch );
  template<>
    const ResKind ResTraits<Pattern>   ::kind( ResKind::pattern );
  template<>
    const ResKind ResTraits<Product>   ::kind( ResKind::product );
  template<>
    const ResKind ResTraits<Script>    ::kind( ResKind::script );
  template<>
    const ResKind ResTraits<SrcPackage>::kind( ResKind::srcpackage );

  std::string ResKind::satIdent( const ResKind & refers_r, const std::string & name_r )
  {
    if ( ! refers_r || refers_r == package || refers_r == srcpackage )
      return name_r;
    return str::form( "%s:%s", refers_r.c_str(), name_r.c_str() );
  }

  /////////////////////////////////////////////////////////////////
} // namespace zypp
///////////////////////////////////////////////////////////////////
