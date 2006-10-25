/*---------------------------------------------------------------------\
 |                          ____ _   __ __ ___                          |
 |                         |__  / \ / / . \ . \                         |
 |                           / / \ V /|  _/  _/                         |
 |                          / /__ | | | | | |                           |
 |                         /_____||_| |_| |_|                           |
 |                                                                      |
 \---------------------------------------------------------------------*/
/** \file	zypp/ui/PatternContents.cc
 *
*/

#include "zypp/ui/PatternContentsImpl.h"

///////////////////////////////////////////////////////////////////
namespace zypp
{ /////////////////////////////////////////////////////////////////
  ///////////////////////////////////////////////////////////////////
  namespace ui
  { /////////////////////////////////////////////////////////////////

    PatternContents::PatternContents( const Pattern::constPtr & pattern )
    : _pimpl( new PatternContents::Impl( pattern ) )
    {}

    std::set<std::string> PatternContents::install_packages() const
    {
      return _pimpl->install_packages();
    }

    /////////////////////////////////////////////////////////////////
  } // namespace ui
  ///////////////////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////
} // namespace zypp
///////////////////////////////////////////////////////////////////
