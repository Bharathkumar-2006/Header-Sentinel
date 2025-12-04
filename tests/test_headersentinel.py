from headersentinel import headersentinel
import pytest

def test_no_args_return_help():
    with pytest.raises(SystemExit) as exc:
     headersentinel.main()

    assert exc.value.code == 12