// Public-header self-containment gate: an empty TU whose sole include is one
// public header must compile on its own. A header relying on a transitive
// standard-library pull (the missing <vector> that <map>/<filesystem> happen
// to drag in today) is a latent break for embedders; this target turns it
// into a build error. Red-green usage: remove the suspect include from the
// header under test and the target must turn red; restore it, green. The CI
// public-header gate only greps third-party includes and cannot see these.

#include <sheller/syscallrun.h>

int main()
{
    return 0;
}
