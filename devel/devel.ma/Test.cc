#include <iostream>
#include <fstream>
#include <sstream>

#include "boost/functional.hpp"

#include "zypp/base/LogControl.h"
#include "zypp/base/LogTools.h"
#include <zypp/base/Logger.h>

#include "zypp/base/Function.h"
#include "zypp/ZYppCallbacks.h"
#include "zypp/Source.h"
#include "zypp/Package.h"
#include "zypp/source/PackageDelta.h"
#include "zypp/source/Applydeltarpm.h"
#include "zypp/detail/ImplConnect.h"
#include "zypp/ExternalProgram.h"
#include "zypp/AutoDispose.h"

using std::endl;
//using namespace std;
using namespace zypp;

bool dt()
{
  const char *const argv[] = { "find", "/", NULL };
  ExternalProgram prog( argv, ExternalProgram::Stderr_To_Stdout, false );
  for ( std::string line = prog.receiveLine(); ! line.empty(); line = prog.receiveLine() )
    {
      DBG << "Applydeltarpm : " << line << endl;
    }
  return( prog.close() == 0 );
}
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
namespace zypp
{

  class SourceProvideFilePolicy
  {
    // source::DownloadFileReport
    //
  public:
    SourceProvideFilePolicy()
    : _failOnChecksumError( false )
    {}

    SourceProvideFilePolicy & failOnChecksumError( bool yesno_r )
    { _failOnChecksumError = yesno_r ; return *this; }

    bool failOnChecksumError() const
    { return _failOnChecksumError; }

  private:
    bool _failOnChecksumError;
  };


  typedef AutoDispose<const Pathname> ManagedFile;

  /////////////////////////////////////////////////////////////////
  ManagedFile sourceProvideFile( Source_Ref source_r,
                                 const source::OnMediaLocation & loc_r,
                                 const SourceProvideFilePolicy & policy_r = SourceProvideFilePolicy() )
  {
    INT << "sourceProvideFile " << loc_r << endl;
    ManagedFile ret( source_r.provideFile( loc_r.filename(), loc_r.medianr() ),
                     boost::bind( &Source_Ref::releaseFile, source_r, _1, loc_r.medianr() ) );

    if ( loc_r.checksum().empty() )
      {
        // no checksum in metadata
        WAR << "No checksum in metadata " << loc_r << endl;
      }
    else
      {
        std::ifstream input( ret->asString().c_str() );
        CheckSum retChecksum( loc_r.checksum().type(), input );
        input.close();

        if ( loc_r.checksum() != retChecksum )
          {
            // failed integity check
            std::ostringstream err;
            err << "File " << ret << " fails integrity check. Expected: [" << loc_r.checksum() << "] Got: [";
            if ( retChecksum.empty() )
                err << "Failed to compute checksum";
            else
                err << retChecksum;
            err << "]";

            if ( policy_r.failOnChecksumError() )
              ZYPP_THROW( Exception( err.str() ) );
            else
              WAR << "NO failOnChecksumError: " << err.str() << endl;
          }
      }

    INT << "Return:  " << ret << endl;
    return ret;
  }

  /////////////////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////

  struct ActionLog
  {
    ActionLog()
    {}
    ~ActionLog()
    {}
    :
  };

  /////////////////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////
  class PackageProvider
  {
    typedef shared_ptr<void>                                       ScopedGuard;
    typedef callback::SendReport<source::DownloadResolvableReport> Report;

    typedef detail::ResImplTraits<Package::Impl>::constPtr PackageImpl_constPtr;
    typedef packagedelta::DeltaRpm                         DeltaRpm;
    typedef packagedelta::PatchRpm                         PatchRpm;


  public:

    PackageProvider( const Package::constPtr & package )
    : _package( package )
    , _implPtr( detail::ImplConnect::resimpl( _package ) )
    {}

    ~PackageProvider()
    {}

  public:

    ManagedFile get() const
    {
      DBG << "provide Package " << _package << endl;
      ScopedGuard guardReport( newReport() );

      //callback::ReceiveReport<source::DownloadFileReport> dumb;
      //callback::TempConnect<source::DownloadFileReport> temp( dumb );


      try
        {
          return doProvidePackage()
        }

      ManagedFile ret( doProvidePackage() );

      if ( ret->empty() )
        {
          ERR << "Failed to provide Package " << _package << endl;
#warning THROW ON ERROR
          return ManagedFile();
        }

      MIL << "provided Package " << _package << " at " << ret << endl;
      return ret;
    }

  private:
    bool considerDeltas() const
    { return applydeltarpm::haveApplydeltarpm(); }

    bool considerPatches() const
    { return true; }

    ManagedFile doProvidePackage() const
    {
      if ( considerDeltas() )
        {
          std::list<DeltaRpm> deltaRpms( _implPtr->deltaRpms() );
          DBG << "deltas: " << deltaRpms.size() << endl;
          if ( ! deltaRpms.empty() )
            {
              for( std::list<DeltaRpm>::const_iterator it = deltaRpms.begin();
                   it != deltaRpms.end(); ++it )
                {
                  DBG << "tryDelta " << *it << endl;
                  ManagedFile ret( tryDelta( *it ) );
                  if ( ! ret->empty() )
                    return ret;
                }
            }
        }

      if ( considerPatches() )
        {
          std::list<PatchRpm> patchRpms( _implPtr->patchRpms() );
          DBG << "patches: " << patchRpms.size() << endl;
          if ( ! patchRpms.empty() )
            {
             for( std::list<PatchRpm>::const_iterator it = patchRpms.begin();
                   it != patchRpms.end(); ++it )
                {
                  DBG << "tryPatch " << *it << endl;
                  ManagedFile ret( tryPatch( *it ) );
                  if ( ! ret->empty() )
                    return ret;
                }
            }
        }

      INT << "Need whole package download!" << endl;

      source::OnMediaLocation().medianr( _package->sourceMediaNr() )
                               .filename( _package->location() )
                               .checksum( _package->checksum() )
                               .downloadsize( _package->archivesize() );

      ManagedFile ret( sourceProvideFile( _package->source(),
                                          source::OnMediaLocation()
                                          .medianr( _package->sourceMediaNr() )
                                          .filename( _package->location() )
                                          .checksum( _package->checksum() ) ) );
      return ret;
    }

    ManagedFile tryDelta( const DeltaRpm & delta_r ) const
    {
      if ( ! applydeltarpm::quickcheck( delta_r.baseversion().sequenceinfo() ) )
        return ManagedFile();

      ManagedFile delta( sourceProvideFile( _package->source(), delta_r.location() ) );
      if ( delta->empty() )
        return ManagedFile();

      if ( ! applydeltarpm::check( delta_r.baseversion().sequenceinfo() ) )
        return ManagedFile();

      Pathname destination( "/tmp/delta.rpm" );
      if ( ! applydeltarpm::provide( delta, destination ) )
        return ManagedFile();

      return ManagedFile( destination, filesystem::unlink );
    }

    ManagedFile tryPatch( const PatchRpm & patch_r ) const
    {
      // installed edition is in baseversions?
      const PatchRpm::BaseVersions & baseversions( patch_r.baseversions() );
      USR << baseversions << endl;
      if ( std::find( baseversions.begin(), baseversions.end(), Edition() ) == baseversions.end() )
        return ManagedFile();

      ManagedFile patch( sourceProvideFile( _package->source(), patch_r.location() ) );
      if ( patch->empty() )
        return ManagedFile();

      return patch;
    }

  private:
    ScopedGuard newReport() const
    {
      _report.reset( new Report );
      return shared_ptr<void>( static_cast<void*>(0),
                               // custom deleter calling _report.reset()
                               // (cast required as reset is overloaded)
                               bind( mem_fun_ref( static_cast<void (shared_ptr<Report>::*)()>(&shared_ptr<Report>::reset) ),
                                     ref(_report) ) );
    }

  private:
    Package::constPtr    _package;
    PackageImpl_constPtr _implPtr;
    mutable shared_ptr<Report>   _report;
  };

  Pathname testProvidePackage( Package::constPtr package )
  {
    if ( package->arch() != Arch_x86_64 )
      return Pathname();

    PackageProvider pkgProvider( package );

    ManagedFile r = pkgProvider.get();
INT << "got" << endl;
    return Pathname();
  }
}

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

#include "Tools.h"
#include "zypp/ZYppFactory.h"
#include "zypp/ZYppCallbacks.h"

namespace zypp
{
  class Dln : public callback::ReceiveReport<media::DownloadProgressReport>
  {
    virtual void reportbegin()
    { _SEC("REPORT") << "+++DownloadProgress" << endl; }
    virtual void reportend()
    { _SEC("REPORT") << "---DownloadProgress" << endl; }
  };

  class Sfp : public callback::ReceiveReport<source::DownloadFileReport>
  {
    virtual void reportbegin()
    { _SEC("REPORT") << "+++source::DownloadFile" << endl; }
    virtual void reportend()
    { _SEC("REPORT") << "---source::DownloadFile" << endl; }
  };


  /////////////////////////////////////////////////////////////////
  template<class _Tp>
    struct Encl
    {
      Encl( const _Tp & v )
      : _v( v )
      {}

      const _Tp & _v;
    };

  template<class _Tp>
    std::ostream & operator<<( std::ostream & str, const Encl<_Tp> & obj )
    { return str << ' ' << obj << ' '; }

  template<class _Tp>
    Encl<_Tp> encl( const _Tp & v )
    { return Encl<_Tp>( v ); }




  class SRP : public callback::ReceiveReport<source::DownloadResolvableReport>
  {
    virtual void reportbegin()
    { _SEC("REPORT") << "+++source::DownloadResolvable" << endl; }


    virtual void start( Resolvable::constPtr resolvable_ptr, Url url )
    { _SEC("REPORT") << encl(resolvable_ptr) << encl(url) << endl; }

    virtual void startDeltaDownload( const Pathname & filename, const ByteCount & downloadsize )
    { _SEC("REPORT") << " " << endl; }

    virtual bool progressDeltaDownload( int value )
    {  _SEC("REPORT") << " " << endl; return true; }

    virtual void problemDeltaDownload( std::string description )
    { _SEC("REPORT") << " " << endl; }

    // Apply delta rpm:
    // - local path of downloaded delta
    // - aplpy is not interruptable
    // - problems are just informal
    virtual void startDeltaApply( const Pathname & filename )
    { _SEC("REPORT") << " " << endl; }

    virtual void progressDeltaApply( int value )
    { _SEC("REPORT") << " " << endl; }

    virtual void problemDeltaApply( std::string description )
    { _SEC("REPORT") << " " << endl; }

    // Dowmload patch rpm:
    // - path below url reported on start()
    // - expected download size (0 if unknown)
    // - download is interruptable
    virtual void startPatchDownload( const Pathname & filename, const ByteCount & downloadsize )
    { _SEC("REPORT") << " " << endl; }

    virtual bool progressPatchDownload( int value )
    {  _SEC("REPORT") << " " << endl; return true; }

    virtual void problemPatchDownload( std::string description )
    { _SEC("REPORT") << " " << endl; }



    virtual bool progress(int value, Resolvable::constPtr resolvable_ptr)
    {  _SEC("REPORT") << " " << endl; return true; }

    virtual Action problem( Resolvable::constPtr resolvable_ptr
                            , Error error
                            , std::string description
                            )
    {  _SEC("REPORT") << " " << endl; return ABORT; }

    virtual void finish(Resolvable::constPtr resolvable_ptr
                         , Error error
                         , std::string reason
                         ) {}

    virtual void reportend()
    { _SEC("REPORT") << "---source::DownloadResolvable" << endl; }
  };
}

void test( const ResObject::constPtr & res )
{
  if ( ! isKind<Package>( res ) )
    return;

  SEC << "Test " << res << endl;

  if ( ! res->source() )
    return;

  try
    {
      MIL << zypp::testProvidePackage( asKind<Package>( res ) ) << endl;
    }
  catch ( Exception & expt )
    {
      ERR << expt << endl;
    }
}

void show( const Pathname & file )
{
  WAR << "show " << PathInfo( file ) << endl;
}

struct ValRelease
{
  ValRelease( int i )
  : _i( i )
  {}
  void operator()( const Pathname & file ) const
  { WAR << "ValRelease " << _i << " " << PathInfo( file ) << endl; }

  int _i;
};

void progressor( unsigned i )
{
  USR << i << "%" << endl;
}


/******************************************************************
**
**      FUNCTION NAME : main
**      FUNCTION TYPE : int
*/
int main( int argc, char * argv[] )
{
  //zypp::base::LogControl::instance().logfile( "log.restrict" );
  INT << "===[START]==========================================" << endl;

  ResPool pool( getZYpp()->pool() );

  Source_Ref src( createSource( "dir:////Local/PATCHES" ) );
  getZYpp()->addResolvables( src.resolvables() );

  MIL << pool << endl;

  dumpRange( MIL, pool.byNameBegin("glibc"), pool.byNameEnd("glibc") ) << endl;

  Dln dnl;
  Sfp sfp;
  SRP srp;
  dnl.connect();
  sfp.connect();
  srp.connect();

  std::for_each( pool.byNameBegin("glibc"), pool.byNameEnd("glibc"), test );

  INT << "===[END]============================================" << endl << endl;
  zypp::base::LogControl::instance().logNothing();
  return 0;
}

