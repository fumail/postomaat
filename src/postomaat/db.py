SQLALCHEMY_AVAILABLE=False
try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import scoped_session, sessionmaker
    SQLALCHEMY_AVAILABLE=True
except:
    pass

_enginecache={}

def get_session(dburl):
    if dburl in _enginecache:
        engine= _enginecache[dburl]
    else:
        engine = create_engine(dburl,pool_size=20,pool_recycle=300)
    _enginecache[dburl]=engine
    maker = sessionmaker(autoflush=True, autocommit=True)
    session = scoped_session(maker)
    session.configure(bind=engine)
    return session


def get_gonnection(dburl):
    return get_session(dburl)    