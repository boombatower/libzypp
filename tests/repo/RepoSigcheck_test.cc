#include <iostream>

#include <boost/test/auto_unit_test.hpp>

#include "zypp/ZYppFactory.h"
#include "zypp/RepoManager.h"
#include "TestSetup.h"

using namespace boost::unit_test;
using namespace zypp;
using std::cout;
using std::endl;

#define TAG cout << "*** " << __PRETTY_FUNCTION__ << endl

TestSetup test( Arch_x86_64 );
const Pathname DATADIR( TESTS_SRC_DIR "/repo/RepoSigcheck" );

// NOTE:


///////////////////////////////////////////////////////////////////

struct KeyRingReceiver : public callback::ReceiveReport<KeyRingReport>
{
  typedef callback::ReceiveReport<KeyRingReport> Base;

  KeyRingReceiver()		{ TAG; connect(); }
  ~KeyRingReceiver()		{ TAG; }

  virtual void reportbegin()	{ TAG; }
  virtual void reportend()	{ TAG; }

  virtual KeyTrust askUserToAcceptKey( const PublicKey &key, const KeyContext &keycontext = KeyContext() )
  {
    TAG; return Base::askUserToAcceptKey( key , keycontext );
  }

  virtual void infoVerify( const std::string & file_r, const PublicKeyData & keyData_r, const KeyContext &keycontext = KeyContext() )
  {
    TAG; return Base::infoVerify( file_r, keyData_r, keycontext );
  }

  virtual bool askUserToAcceptUnsignedFile( const std::string &file, const KeyContext &keycontext = KeyContext() )
  {
    TAG; return Base::askUserToAcceptUnsignedFile( file, keycontext );
  }

  virtual bool askUserToAcceptUnknownKey( const std::string &file, const std::string &id, const KeyContext &keycontext = KeyContext() )
  {
    TAG; return Base::askUserToAcceptUnknownKey( file, id, keycontext );
  }

  virtual bool askUserToAcceptVerificationFailed( const std::string &file, const PublicKey &key, const KeyContext &keycontext = KeyContext() )
  {
    TAG; return Base::askUserToAcceptVerificationFailed( file, key, keycontext );
  }
} callback;

///////////////////////////////////////////////////////////////////
/*
 *  r: check repo signature, unsigned repos enforce p
 *  R: check repo signature is mandatory, confirm unsigned repos
 *
 *  p: check package signature, if repo was not checked
 *  P: check package signature always
 * (): gpgcheck overrules explicit pkg_gpgcheck config value
 *                    pkg_
 * gpgcheck1|     *       0       1
 * -----------------------------------
 *         *|     r/p     R/(p)   r/P
 * repo_   0|       P       (P)     P
 *         1|     R/p     R/(p)   R/P
 *
 *                    pkg_
 * gpgcheck0|     *       0       1
 * -----------------------------------
 *         *|                       P
 * repo_   0|                       P
 *         1|     R       R       R/P
 * \endcode
 */
BOOST_AUTO_TEST_CASE(init)
{
  ZConfig & zcfg( ZConfig::instance() );

  RepoInfo repo;
  std::initializer_list<TriBool> tribools( { TriBool(indeterminate), TriBool(true), TriBool(false) } );

  // global zconfig values...
  for ( bool g_GpgCheck : { true, false } )
  {
    zcfg.setGpgCheck( g_GpgCheck );
    for ( TriBool g_RepoGpgCheck : tribools )
    {
      zcfg.setRepoGpgCheck( g_RepoGpgCheck );
      for ( TriBool g_PkgGpgCheck : tribools )
      {
	zcfg.setPkgGpgCheck( g_PkgGpgCheck );

	// .repo values
	for ( TriBool r_GpgCheck : tribools )
	{
	  repo.setGpgCheck( r_GpgCheck );
	  for ( TriBool r_RepoGpgCheck : tribools )
	  {
	    repo.setRepoGpgCheck( r_RepoGpgCheck );
	    for ( TriBool r_PkgGpgCheck : tribools )
	    {
	      repo.setPkgGpgCheck( r_PkgGpgCheck );
	      // check the repo methods returning what to do:
	      bool	cfgGpgCheck	= indeterminate(r_GpgCheck)     ? g_GpgCheck     : bool(r_GpgCheck);
	      TriBool	cfgRepoGpgCheck	= indeterminate(r_RepoGpgCheck) ? g_RepoGpgCheck : r_RepoGpgCheck;
	      TriBool	cfgPkgGpgCheck	= indeterminate(r_PkgGpgCheck)  ? g_PkgGpgCheck  : r_PkgGpgCheck;
#if 1
	      cout << cfgGpgCheck << "\t" << cfgRepoGpgCheck << "\t" << cfgPkgGpgCheck
		   << "\t(" << r_GpgCheck << "," << g_GpgCheck << ")"
		   << "\t(" << r_RepoGpgCheck << "," << g_RepoGpgCheck << ")"
		   << "\t(" << r_PkgGpgCheck << "," <<  g_PkgGpgCheck<< ")"
	           << endl;
#endif

	      // default gpgCeck follows config
	      BOOST_CHECK_EQUAL( repo.gpgCheck(), cfgGpgCheck );

	      // repoGpgCheck defined or follow gpgCheck
	      bool willCheckRepo  = repo.repoGpgCheck();
	      bool mandatoryCheck = repo.repoGpgCheckIsMandatory();

	      if ( mandatoryCheck )	// be a subset of willCheckRepo!
		BOOST_CHECK_EQUAL( willCheckRepo, mandatoryCheck );

	      if ( indeterminate(cfgRepoGpgCheck) )
		BOOST_CHECK_EQUAL( willCheckRepo, cfgGpgCheck );
	      else
		BOOST_CHECK_EQUAL( willCheckRepo, bool(cfgRepoGpgCheck) );

	      // pkgGpgCheck may depend on the repoGpgCheck result
	      for ( TriBool r_validSignature : tribools )	// indeterminate <==> unsigned repo
	      {
		if ( cfgGpgCheck )
		{
		  if ( cfgPkgGpgCheck )
		    BOOST_CHECK_EQUAL( repo.pkgGpgCheck(), true );
		  else if ( !cfgRepoGpgCheck )
		    BOOST_CHECK_EQUAL( repo.pkgGpgCheck(), true );
		  else
		    BOOST_CHECK_EQUAL( repo.pkgGpgCheck(), !bool(r_validSignature) ); // TriBool: Not the same as `bool(!r_validSignature)`!
		}
		else	// check only if PkgCheck is explicitly ON
		{
		  BOOST_CHECK_EQUAL( repo.pkgGpgCheck(), bool(cfgPkgGpgCheck) );
		}
	      }
	    }
	  }
	}
      }
    }
  }
}


BOOST_AUTO_TEST_CASE(unsigned_repo)
{
  test.loadRepo( DATADIR/"unsigned_repo", "unsigned_repo" );
}

BOOST_AUTO_TEST_CASE(signed_repo)
{
  //test.loadRepo( DATADIR/"signed_repo", "signed_repo" );
}


BOOST_AUTO_TEST_CASE(summary)
{
  RepoManager  rm( test.repomanager() );
  sat::Pool    pool( test.satpool() );

  cout << KeyRing::defaultAccept() << endl;

  cout << endl;
  cout << pool << endl;
  for ( auto && repo : pool.repos() )
  {
    cout << repo << endl;
    cout << repo.info() << endl;
  }
}
