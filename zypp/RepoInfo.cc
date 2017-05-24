/*---------------------------------------------------------------------\
|                          ____ _   __ __ ___                          |
|                         |__  / \ / / . \ . \                         |
|                           / / \ V /|  _/  _/                         |
|                          / /__ | | | | | |                           |
|                         /_____||_| |_| |_|                           |
|                                                                      |
\---------------------------------------------------------------------*/
/** \file	zypp/RepoInfo.cc
 *
*/
#include <iostream>
#include <vector>

#include "zypp/base/LogTools.h"
#include "zypp/base/DefaultIntegral.h"
#include "zypp/parser/xml/XmlEscape.h"

#include "zypp/RepoInfo.h"
#include "zypp/Glob.h"
#include "zypp/TriBool.h"
#include "zypp/Pathname.h"
#include "zypp/ZConfig.h"
#include "zypp/repo/RepoMirrorList.h"
#include "zypp/ExternalProgram.h"
#include "zypp/media/MediaAccess.h"

#include "zypp/base/IOStream.h"
#include "zypp/base/InputStream.h"
#include "zypp/parser/xml/Reader.h"

using std::endl;
using zypp::xml::escape;

///////////////////////////////////////////////////////////////////
namespace zypp
{ /////////////////////////////////////////////////////////////////

  ///////////////////////////////////////////////////////////////////
  //
  //	CLASS NAME : RepoInfo::Impl
  //
  /** RepoInfo implementation. */
  struct RepoInfo::Impl
  {
    Impl()
      : _rawGpgCheck( indeterminate )
      , _rawRepoGpgCheck( indeterminate )
      , _rawPkgGpgCheck( indeterminate )
      , _validRepoSignature( indeterminate )
      ,	keeppackages(indeterminate)
      , _mirrorListForceMetalink(false)
      , type(repo::RepoType::NONE_e)
      , emptybaseurls(false)
    {}

    ~Impl()
    {}

  public:
    static const unsigned defaultPriority = 99;
    static const unsigned noPriority = unsigned(-1);

    void setProbedType( const repo::RepoType & t ) const
    {
      if ( type == repo::RepoType::NONE
           && t != repo::RepoType::NONE )
      {
        // lazy init!
        const_cast<Impl*>(this)->type = t;
      }
    }

  public:
    /** Path to a license tarball in case it exists in the repo. */
    Pathname licenseTgz() const
    {
      Pathname ret;
      if ( !metadataPath().empty() )
      {
	filesystem::Glob g;
	g.add( metadataPath() / path / "repodata/*license.tar.gz" );
	if ( g.empty() )
	  g.add( metadataPath() / path / "license.tar.gz" );

	if ( !g.empty() )
	  ret = *g.begin();
      }
      return ret;
    }

    const RepoVariablesReplacedUrlList & baseUrls() const
    {
      const Url & mlurl( _mirrorListUrl.transformed() );	// Variables replaced!
      if ( _baseUrls.empty() && ! mlurl.asString().empty() )
      {
        emptybaseurls = true;
        DBG << "MetadataPath: " << metadataPath() << endl;
	repo::RepoMirrorList rmurls( mlurl, metadataPath(), _mirrorListForceMetalink );
	_baseUrls.raw().insert( _baseUrls.raw().end(), rmurls.getUrls().begin(), rmurls.getUrls().end() );
      }
      return _baseUrls;
    }

    RepoVariablesReplacedUrlList & baseUrls()
    { return _baseUrls; }

    bool baseurl2dump() const
    { return !emptybaseurls && !_baseUrls.empty(); }


    const RepoVariablesReplacedUrlList & gpgKeyUrls() const
    { return _gpgKeyUrls; }

    RepoVariablesReplacedUrlList & gpgKeyUrls()
    { return _gpgKeyUrls; }


    const std::set<std::string> & contentKeywords() const
    { hasContent()/*init if not yet done*/; return _keywords.second; }

    void addContent( const std::string & keyword_r )
    { _keywords.second.insert( keyword_r ); if ( ! hasContent() ) _keywords.first = true; }

    bool hasContent() const
    {
      if ( !_keywords.first && ! metadataPath().empty() )
      {
	// HACK directly check master index file until RepoManager offers
	// some content probing and zypper uses it.
	/////////////////////////////////////////////////////////////////
	MIL << "Empty keywords...." << metadataPath() << endl;
	Pathname master;
	if ( PathInfo( (master=metadataPath()/"/repodata/repomd.xml") ).isFile() )
	{
	  //MIL << "GO repomd.." << endl;
	  xml::Reader reader( master );
	  while ( reader.seekToNode( 2, "content" ) )
	  {
	    _keywords.second.insert( reader.nodeText().asString() );
	    reader.seekToEndNode( 2, "content" );
	  }
	  _keywords.first = true;	// valid content in _keywords even if empty
	}
	else if ( PathInfo( (master=metadataPath()/"/content") ).isFile() )
	{
	  //MIL << "GO content.." << endl;
	  iostr::forEachLine( InputStream( master ),
                            [this]( int num_r, std::string line_r )->bool
                            {
                              if ( str::startsWith( line_r, "REPOKEYWORDS" ) )
			      {
				std::vector<std::string> words;
				if ( str::split( line_r, std::back_inserter(words) ) > 1
				  && words[0].length() == 12 /*"REPOKEYWORDS"*/ )
				{
				  this->_keywords.second.insert( ++words.begin(), words.end() );
				}
				return true; // mult. occurrances are ok.
			      }
			      return( ! str::startsWith( line_r, "META " ) );	// no need to parse into META section.
			    } );
	  _keywords.first = true;	// valid content in _keywords even if empty
	}
	/////////////////////////////////////////////////////////////////
      }
      return _keywords.first;
    }

    bool hasContent( const std::string & keyword_r ) const
    { return( hasContent() && _keywords.second.find( keyword_r ) != _keywords.second.end() ); }

    /** Signature check result needs to be stored/retrieved from _metadataPath.
     * Don't call them from outside validRepoSignature/setValidRepoSignature
     */
    //@{
    TriBool internalValidRepoSignature() const
    {
      if ( ! indeterminate(_validRepoSignature) )		return _validRepoSignature;
      // check metadata:
      if ( ! metadataPath().empty() )
      {
	//TODO: a missing ".repo_gpgcheck" might be plaindir(no Downloader) or not yet refreshed signed repo!
	TriBool linkval = triBoolFromPath( metadataPath() / ".repo_gpgcheck" );
	return linkval;
      }
      return indeterminate;
    }

    void internalSetValidRepoSignature( TriBool value_r )
    {
      if ( PathInfo(metadataPath()).isDir() )
      {
	Pathname gpgcheckFile( metadataPath() / ".repo_gpgcheck" );
	if ( PathInfo(gpgcheckFile).isExist() )
	{
	  TriBool linkval( indeterminate );
	  if ( triBoolFromPath( gpgcheckFile, linkval ) && linkval == value_r )
	    return;	// existing symlink fits value_r
	  else
	    filesystem::unlink( gpgcheckFile );	// will write a new one
	}
	filesystem::symlink( asString(value_r), gpgcheckFile );
      }
      _validRepoSignature = value_r;
    }

    bool triBoolFromPath( const Pathname & path_r, TriBool & ret_r ) const
    {
      static const Pathname truePath( "true" );
      static const Pathname falsePath( "false" );
      static const Pathname indeterminatePath( "indeterminate" );
      Pathname linkval( filesystem::readlink( path_r ) );
      bool known = true;
      if ( linkval == truePath )
	ret_r = true;
      else if ( linkval == falsePath )
	ret_r = false;
      else if ( linkval == indeterminatePath )
	ret_r = indeterminate;
      else
	known = false;
      return known;
    }

    TriBool triBoolFromPath( const Pathname & path_r ) const
    { TriBool ret(indeterminate); triBoolFromPath( path_r, ret ); return ret; }

    //@}

  public:
    TriBool _rawGpgCheck;	///< default gpgcheck behavior: Y/N/ZConf
    TriBool _rawRepoGpgCheck;	///< need to check repo sign.: Y/N/(ZConf(Y/N/gpgCheck))
    TriBool _rawPkgGpgCheck;	///< need to check pkg sign.: Y/N/(ZConf(Y/N/gpgCheck))

    bool cfgGpgCheck() const
    { return indeterminate(_rawGpgCheck) ? ZConfig::instance().gpgCheck() : (bool)_rawGpgCheck; }
    TriBool cfgRepoGpgCheck() const
    { return indeterminate(_rawRepoGpgCheck) ? ZConfig::instance().repoGpgCheck() : _rawRepoGpgCheck; }
    TriBool cfgPkgGpgCheck() const
    { return indeterminate(_rawPkgGpgCheck) ? ZConfig::instance().pkgGpgCheck() : _rawPkgGpgCheck; }

  private:
    TriBool _validRepoSignature;///< have  signed and valid repo metadata
  public:
    TriBool keeppackages;
    RepoVariablesReplacedUrl _mirrorListUrl;
    bool                     _mirrorListForceMetalink;
    repo::RepoType type;
    Pathname path;
    std::string service;
    std::string targetDistro;

    void metadataPath( Pathname new_r )
    { _metadataPath = std::move( new_r ); }

    void packagesPath( Pathname new_r )
    { _packagesPath = std::move( new_r ); }

    bool usesAutoMethadataPaths() const
    { return str::hasSuffix( _metadataPath.asString(), "/%AUTO%" ); }

    Pathname metadataPath() const
    {
      if ( usesAutoMethadataPaths() )
	return _metadataPath.dirname() / "%RAW%";
      return _metadataPath;
    }

    Pathname packagesPath() const
    {
      if ( _packagesPath.empty() && usesAutoMethadataPaths() )
	return _metadataPath.dirname() / "%PKG%";
      return _packagesPath;
    }

    DefaultIntegral<unsigned,defaultPriority> priority;
    mutable bool emptybaseurls;
    repo::RepoVariablesUrlReplacer replacer;

  private:
    Pathname _metadataPath;
    Pathname _packagesPath;

    mutable RepoVariablesReplacedUrlList _baseUrls;
    mutable std::pair<FalseBool, std::set<std::string> > _keywords;

    RepoVariablesReplacedUrlList _gpgKeyUrls;

    friend Impl * rwcowClone<Impl>( const Impl * rhs );
    /** clone for RWCOW_pointer */
    Impl * clone() const
    { return new Impl( *this ); }
  };
  ///////////////////////////////////////////////////////////////////

  /** \relates RepoInfo::Impl Stream output */
  inline std::ostream & operator<<( std::ostream & str, const RepoInfo::Impl & obj )
  {
    return str << "RepoInfo::Impl";
  }

  ///////////////////////////////////////////////////////////////////
  //
  //	CLASS NAME : RepoInfo
  //
  ///////////////////////////////////////////////////////////////////

  const RepoInfo RepoInfo::noRepo;

  RepoInfo::RepoInfo()
  : _pimpl( new Impl() )
  {}

  RepoInfo::~RepoInfo()
  {}

  unsigned RepoInfo::priority() const
  { return _pimpl->priority; }

  unsigned RepoInfo::defaultPriority()
  { return Impl::defaultPriority; }

  unsigned RepoInfo::noPriority()
  { return Impl::noPriority; }

  void RepoInfo::setPriority( unsigned newval_r )
  { _pimpl->priority = newval_r ? newval_r : Impl::defaultPriority; }


  bool RepoInfo::gpgCheck() const
  { return _pimpl->cfgGpgCheck(); }

  void RepoInfo::setGpgCheck( TriBool value_r )
  { _pimpl->_rawGpgCheck = value_r; }

  void RepoInfo::setGpgCheck( bool value_r ) // deprecated legacy and for squid
  { setGpgCheck( TriBool(value_r) ); }


  bool RepoInfo::repoGpgCheck() const
  {
    const TriBool & cfg( _pimpl->cfgRepoGpgCheck() );
    if ( !indeterminate(cfg) )
      return cfg;
    return gpgCheck();	// no preference: follow gpgCheck
  }

  bool RepoInfo::repoGpgCheckIsMandatory() const
  {
    const TriBool & cfg( _pimpl->cfgRepoGpgCheck() );
    if ( !indeterminate(cfg) )
      return cfg;
    return gpgCheck() && !_pimpl->cfgPkgGpgCheck();
  }

  void RepoInfo::setRepoGpgCheck( TriBool value_r )
  { _pimpl->_rawRepoGpgCheck = value_r; }


  bool RepoInfo::pkgGpgCheck() const
  {

    FIXIT!


    const TriBool & cfg( _pimpl->cfgPkgGpgCheck() );
    if ( !indeterminate(cfg) )
      return cfg;
    // no preference: follow gpgCheck and check package if repo signature not available or not checked
    return gpgCheck() && ( !repoGpgCheck() || !(bool)validRepoSignature() );	// !(bool)TriBool ==> false or indeterminate
  }

  void RepoInfo::setPkgGpgCheck( TriBool value_r )
  { _pimpl->_rawPkgGpgCheck = value_r; }

  void RepoInfo::getRawGpgChecks( TriBool & g_r, TriBool & r_r, TriBool & p_r ) const
  {
    g_r = _pimpl->_rawGpgCheck;
    r_r = _pimpl->_rawRepoGpgCheck;
    p_r = _pimpl->_rawPkgGpgCheck;
  }

  TriBool RepoInfo::validRepoSignature() const
  {
    TriBool ret = _pimpl->internalValidRepoSignature();
    // keep indeterminate(=unsigned) but invalidate any signature if !repoGpgCheck
    if ( !indeterminate(ret) && !repoGpgCheck() )
      ret = false;
    return ret;
  }

  void RepoInfo::setValidRepoSignature( TriBool value_r )
  { _pimpl->internalSetValidRepoSignature( value_r ); }


  void RepoInfo::setMirrorListUrl( const Url & url_r )	// Raw
  { _pimpl->_mirrorListUrl.raw() = url_r; _pimpl->_mirrorListForceMetalink = false; }

  void  RepoInfo::setMetalinkUrl( const Url & url_r )	// Raw
  { _pimpl->_mirrorListUrl.raw() = url_r; _pimpl->_mirrorListForceMetalink = true; }

  void RepoInfo::setGpgKeyUrls( url_set urls )
  { _pimpl->gpgKeyUrls().raw().swap( urls ); }

  void RepoInfo::setGpgKeyUrl( const Url & url_r )
  {
    _pimpl->gpgKeyUrls().raw().clear();
    _pimpl->gpgKeyUrls().raw().push_back( url_r );
  }

  void RepoInfo::addBaseUrl( const Url & url_r )
  {
    for ( const auto & url : _pimpl->baseUrls().raw() )	// Raw unique!
      if ( url == url_r )
	return;
    _pimpl->baseUrls().raw().push_back( url_r );
  }

  void RepoInfo::setBaseUrl( const Url & url_r )
  {
    _pimpl->baseUrls().raw().clear();
    _pimpl->baseUrls().raw().push_back( url_r );
  }

  void RepoInfo::setBaseUrls( url_set urls )
  { _pimpl->baseUrls().raw().swap( urls ); }

  void RepoInfo::setPath( const Pathname &path )
  { _pimpl->path = path; }

  void RepoInfo::setType( const repo::RepoType &t )
  { _pimpl->type = t; }

  void RepoInfo::setProbedType( const repo::RepoType &t ) const
  { _pimpl->setProbedType( t ); }


  void RepoInfo::setMetadataPath( const Pathname &path )
  { _pimpl->metadataPath( path ); }

  void RepoInfo::setPackagesPath( const Pathname &path )
  { _pimpl->packagesPath( path ); }

  void RepoInfo::setKeepPackages( bool keep )
  { _pimpl->keeppackages = keep; }

  void RepoInfo::setService( const std::string& name )
  { _pimpl->service = name; }

  void RepoInfo::setTargetDistribution( const std::string & targetDistribution )
  { _pimpl->targetDistro = targetDistribution; }

  bool RepoInfo::keepPackages() const
  { return indeterminate(_pimpl->keeppackages) ? false : (bool)_pimpl->keeppackages; }

  Pathname RepoInfo::metadataPath() const
  { return _pimpl->metadataPath(); }

  Pathname RepoInfo::packagesPath() const
  { return _pimpl->packagesPath(); }

  bool RepoInfo::usesAutoMethadataPaths() const
  { return _pimpl->usesAutoMethadataPaths(); }

  repo::RepoType RepoInfo::type() const
  { return _pimpl->type; }

  Url RepoInfo::mirrorListUrl() const			// Variables replaced!
  { return _pimpl->_mirrorListUrl.transformed(); }

  Url RepoInfo::rawMirrorListUrl() const		// Raw
  { return _pimpl->_mirrorListUrl.raw(); }

  bool RepoInfo::gpgKeyUrlsEmpty() const
  { return _pimpl->gpgKeyUrls().empty(); }

  RepoInfo::urls_size_type RepoInfo::gpgKeyUrlsSize() const
  { return _pimpl->gpgKeyUrls().size(); }

  RepoInfo::url_set RepoInfo::gpgKeyUrls() const	// Variables replaced!
  { return _pimpl->gpgKeyUrls().transformed(); }

  RepoInfo::url_set RepoInfo::rawGpgKeyUrls() const	// Raw
  { return _pimpl->gpgKeyUrls().raw(); }

  Url RepoInfo::gpgKeyUrl() const			// Variables replaced!
  { return( _pimpl->gpgKeyUrls().empty() ? Url() : *_pimpl->gpgKeyUrls().transformedBegin() ); }

  Url RepoInfo::rawGpgKeyUrl() const			// Raw
  { return( _pimpl->gpgKeyUrls().empty() ? Url() : *_pimpl->gpgKeyUrls().rawBegin() ) ; }

  RepoInfo::url_set RepoInfo::baseUrls() const		// Variables replaced!
  { return _pimpl->baseUrls().transformed(); }

  RepoInfo::url_set RepoInfo::rawBaseUrls() const	// Raw
  { return _pimpl->baseUrls().raw(); }

  Pathname RepoInfo::path() const
  { return _pimpl->path; }

  std::string RepoInfo::service() const
  { return _pimpl->service; }

  std::string RepoInfo::targetDistribution() const
  { return _pimpl->targetDistro; }

  Url RepoInfo::rawUrl() const
  { return( _pimpl->baseUrls().empty() ? Url() : *_pimpl->baseUrls().rawBegin() ); }

  RepoInfo::urls_const_iterator RepoInfo::baseUrlsBegin() const
  { return _pimpl->baseUrls().transformedBegin(); }

  RepoInfo::urls_const_iterator RepoInfo::baseUrlsEnd() const
  { return _pimpl->baseUrls().transformedEnd(); }

  RepoInfo::urls_size_type RepoInfo::baseUrlsSize() const
  { return _pimpl->baseUrls().size(); }

  bool RepoInfo::baseUrlsEmpty() const
  { return _pimpl->baseUrls().empty(); }

  bool RepoInfo::baseUrlSet() const
  { return _pimpl->baseurl2dump(); }

  const std::set<std::string> & RepoInfo::contentKeywords() const
  { return _pimpl->contentKeywords(); }

  void RepoInfo::addContent( const std::string & keyword_r )
  { _pimpl->addContent( keyword_r ); }

  bool RepoInfo::hasContent() const
  { return _pimpl->hasContent(); }

  bool RepoInfo::hasContent( const std::string & keyword_r ) const
  { return _pimpl->hasContent( keyword_r ); }

  ///////////////////////////////////////////////////////////////////

  bool RepoInfo::hasLicense() const
  {
    return !_pimpl->licenseTgz().empty();
  }

  bool RepoInfo::needToAcceptLicense() const
  {
    static const std::string noAcceptanceFile = "no-acceptance-needed\n";
    bool accept = true;

    const Pathname & licenseTgz( _pimpl->licenseTgz() );
    if ( licenseTgz.empty() )
      return false;     // no licenses at all

    ExternalProgram::Arguments cmd;
    cmd.push_back( "tar" );
    cmd.push_back( "-t" );
    cmd.push_back( "-z" );
    cmd.push_back( "-f" );
    cmd.push_back( licenseTgz.asString() );

    ExternalProgram prog( cmd, ExternalProgram::Stderr_To_Stdout );
    for ( std::string output( prog.receiveLine() ); output.length(); output = prog.receiveLine() )
    {
      if ( output == noAcceptanceFile )
      {
        accept = false;
      }
    }
    MIL << "License for " << name() << " has to be accepted: " << (accept?"true":"false" ) << endl;
    return accept;
  }

  std::string RepoInfo::getLicense( const Locale & lang_r )
  { return const_cast<const RepoInfo *>(this)->getLicense( lang_r );  }

  std::string RepoInfo::getLicense( const Locale & lang_r ) const
  {
    LocaleSet avlocales( getLicenseLocales() );
    if ( avlocales.empty() )
      return std::string();

    Locale getLang( Locale::bestMatch( avlocales, lang_r ) );
    if ( !getLang && avlocales.find( Locale::noCode ) == avlocales.end() )
    {
      WAR << "License.tar.gz contains no fallback text! " << *this << endl;
      // Using the fist locale instead of returning no text at all.
      // So the user might recognize that there is a license, even if he
      // can't read it.
      getLang = *avlocales.begin();
    }

    // now extract the license file.
    static const std::string licenseFileFallback( "license.txt" );
    std::string licenseFile( !getLang ? licenseFileFallback
				      : str::form( "license.%s.txt", getLang.c_str() ) );

    ExternalProgram::Arguments cmd;
    cmd.push_back( "tar" );
    cmd.push_back( "-x" );
    cmd.push_back( "-z" );
    cmd.push_back( "-O" );
    cmd.push_back( "-f" );
    cmd.push_back( _pimpl->licenseTgz().asString() ); // if it not exists, avlocales was empty.
    cmd.push_back( licenseFile );

    std::string ret;
    ExternalProgram prog( cmd, ExternalProgram::Discard_Stderr );
    for ( std::string output( prog.receiveLine() ); output.length(); output = prog.receiveLine() )
    {
      ret += output;
    }
    prog.close();
    return ret;
  }

  LocaleSet RepoInfo::getLicenseLocales() const
  {
    const Pathname & licenseTgz( _pimpl->licenseTgz() );
    if ( licenseTgz.empty() )
      return LocaleSet();

    ExternalProgram::Arguments cmd;
    cmd.push_back( "tar" );
    cmd.push_back( "-t" );
    cmd.push_back( "-z" );
    cmd.push_back( "-f" );
    cmd.push_back( licenseTgz.asString() );

    LocaleSet ret;
    ExternalProgram prog( cmd, ExternalProgram::Stderr_To_Stdout );
    for ( std::string output( prog.receiveLine() ); output.length(); output = prog.receiveLine() )
    {
      static const C_Str license( "license." );
      static const C_Str dotTxt( ".txt\n" );
      if ( str::hasPrefix( output, license ) && str::hasSuffix( output, dotTxt ) )
      {
        if ( output.size() <= license.size() +  dotTxt.size() ) // license.txt
          ret.insert( Locale() );
        else
          ret.insert( Locale( std::string( output.c_str()+license.size(), output.size()- license.size() - dotTxt.size() ) ) );
      }
    }
    prog.close();
    return ret;
  }

  ///////////////////////////////////////////////////////////////////

  std::ostream & RepoInfo::dumpOn( std::ostream & str ) const
  {
    RepoInfoBase::dumpOn(str);
    if ( _pimpl->baseurl2dump() )
    {
      for ( const auto & url : _pimpl->baseUrls().raw() )
      {
        str << "- url         : " << url << std::endl;
      }
    }

    // print if non empty value
    auto strif( [&] ( const std::string & tag_r, const std::string & value_r ) {
      if ( ! value_r.empty() )
	str << tag_r << value_r << std::endl;
    });

    strif( (_pimpl->_mirrorListForceMetalink ? "- metalink    : " : "- mirrorlist  : "), rawMirrorListUrl().asString() );
    strif( "- path        : ", path().asString() );
    str << "- type        : " << type() << std::endl;
    str << "- priority    : " << priority() << std::endl;

    // Yes No Default(Y) Default(N)
#define OUTS(T,B) ( indeterminate(T) ? (std::string("D(")+(B?"Y":"N")+")") : ((bool)T?"Y":"N") )
    str << "- gpgcheck    : " << OUTS(_pimpl->_rawGpgCheck,gpgCheck())
                              << " repo" << OUTS(_pimpl->_rawRepoGpgCheck,repoGpgCheck())
			      << " sig" << asString( validRepoSignature(), "?", "Y", "N" )
			      << " pkg" << OUTS(_pimpl->_rawPkgGpgCheck,pkgGpgCheck())
			      << std::endl;
#undef OUTS

    for ( const auto & url : _pimpl->gpgKeyUrls().raw() )
    {
      str << "- gpgkey      : " << url << std::endl;
    }

    if ( ! indeterminate(_pimpl->keeppackages) )
      str << "- keeppackages: " << keepPackages() << std::endl;

    strif( "- service     : ", service() );
    strif( "- targetdistro: ", targetDistribution() );
    strif( "- filePath:     ", filepath().asString() );
    strif( "- metadataPath: ", metadataPath().asString() );
    strif( "- packagesPath: ", packagesPath().asString() );

    return str;
  }

  std::ostream & RepoInfo::dumpAsIniOn( std::ostream & str ) const
  {
    RepoInfoBase::dumpAsIniOn(str);

    if ( _pimpl->baseurl2dump() )
    {
      str << "baseurl=";
      std::string indent;
      for ( const auto & url : _pimpl->baseUrls().raw() )
      {
        str << indent << url << endl;
	if ( indent.empty() ) indent = "        ";	// "baseurl="
      }
    }

    if ( ! _pimpl->path.empty() )
      str << "path="<< path() << endl;

    if ( ! (rawMirrorListUrl().asString().empty()) )
      str << (_pimpl->_mirrorListForceMetalink ? "metalink=" : "mirrorlist=") << rawMirrorListUrl() << endl;

    str << "type=" << type().asString() << endl;

    if ( priority() != defaultPriority() )
      str << "priority=" << priority() << endl;

    if ( ! indeterminate(_pimpl->_rawGpgCheck) )
      str << "gpgcheck=" << (_pimpl->_rawGpgCheck ? "1" : "0") << endl;

    if ( ! indeterminate(_pimpl->_rawRepoGpgCheck) )
      str << "repo_gpgcheck=" << (_pimpl->_rawRepoGpgCheck ? "1" : "0") << endl;

    if ( ! indeterminate(_pimpl->_rawPkgGpgCheck) )
      str << "pkg_gpgcheck=" << (_pimpl->_rawPkgGpgCheck ? "1" : "0") << endl;

    {
      std::string indent( "gpgkey=");
      for ( const auto & url : _pimpl->gpgKeyUrls().raw() )
      {
	str << indent << url << endl;
	if ( indent[0] != ' ' )
	  indent = "       ";
      }
    }

    if (!indeterminate(_pimpl->keeppackages))
      str << "keeppackages=" << keepPackages() << endl;

    if( ! service().empty() )
      str << "service=" << service() << endl;

    return str;
  }

  std::ostream & RepoInfo::dumpAsXmlOn( std::ostream & str, const std::string & content ) const
  {
    std::string tmpstr;
    str
      << "<repo"
      << " alias=\"" << escape(alias()) << "\""
      << " name=\"" << escape(name()) << "\"";
    if (type() != repo::RepoType::NONE)
      str << " type=\"" << type().asString() << "\"";
    str
      << " priority=\"" << priority() << "\""
      << " enabled=\"" << enabled() << "\""
      << " autorefresh=\"" << autorefresh() << "\""
      << " gpgcheck=\"" << gpgCheck() << "\""
      << " repo_gpgcheck=\"" << repoGpgCheck() << "\""
      << " pkg_gpgcheck=\"" << pkgGpgCheck() << "\"";
    if (!(tmpstr = gpgKeyUrl().asString()).empty())
      str << " gpgkey=\"" << escape(tmpstr) << "\"";
    if (!(tmpstr = mirrorListUrl().asString()).empty())
      str << (_pimpl->_mirrorListForceMetalink ? " metalink=\"" : " mirrorlist=\"") << escape(tmpstr) << "\"";
    str << ">" << endl;

    if ( _pimpl->baseurl2dump() )
    {
      for_( it, baseUrlsBegin(), baseUrlsEnd() )	// !transform iterator replaces variables
	str << "<url>" << escape((*it).asString()) << "</url>" << endl;
    }

    str << "</repo>" << endl;
    return str;
  }


  std::ostream & operator<<( std::ostream & str, const RepoInfo & obj )
  {
    return obj.dumpOn(str);
  }


  /////////////////////////////////////////////////////////////////
} // namespace zypp
///////////////////////////////////////////////////////////////////
