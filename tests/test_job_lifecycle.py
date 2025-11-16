from app.tasks import _fmt_ts_for_name

def test_fmt_ts_for_name():
    import datetime
    dt = datetime.datetime(2024, 1, 2, 3, 4, 5)
    assert _fmt_ts_for_name(dt) == "02012024-03:04:05"
