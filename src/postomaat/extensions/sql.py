# -*- coding: UTF-8 -*-
import logging

SQLALCHEMY_AVAILABLE=False
try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import scoped_session, sessionmaker
    SQLALCHEMY_AVAILABLE=True
except ImportError:
    pass
ENABLED = SQLALCHEMY_AVAILABLE # fuglu compatibility


_sessmaker = None
_engines = {}


def get_session(connectstring, **kwargs):
    global SQLALCHEMY_AVAILABLE
    global _sessmaker
    global _engines

    if not SQLALCHEMY_AVAILABLE:
        raise Exception("sql extension not enabled")

    if connectstring in _engines:
        engine = _engines[connectstring]
    else:
        engine = create_engine(connectstring, pool_recycle=20)
        _engines[connectstring] = engine

    if _sessmaker is None:
        _sessmaker = sessionmaker(autoflush=True, autocommit=True, **kwargs)

    session = scoped_session(_sessmaker)
    session.configure(bind=engine)
    return session



def get_domain_setting(domain, dbconnection, sqlquery, cache, cachename, default_value=None, logger=None):
    if logger is None:
        logger = logging.getLogger()

    cachekey = '%s-%s' % (cachename, domain)
    cached = cache.get_cache(cachekey)
    if cached is not None:
        logger.debug("got cached setting for %s" % domain)
        return cached

    settings = default_value

    try:
        session = get_session(dbconnection)

        # get domain settings
        dom = session.execute(sqlquery, {'domain': domain}).fetchall()

        if not dom or not dom[0] or len(dom[0]) == 0:
            logger.debug(
                "Can not load domain setting - domain %s not found. Using default settings." % domain)
        else:
            settings = dom[0][0]

        session.close()

    except Exception as e:
        logger.error("Exception while loading setting for %s : %s" % (domain, str(e)))

    cache.put_cache(cachekey, settings)
    logger.debug("refreshed setting for %s" % domain)
    return settings