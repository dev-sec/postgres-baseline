# DevSec PostgreSQL Baseline

This Compliance Profile ensures, that all hardening projects keep the same quality.

- https://github.com/dev-sec/chef-postgres-hardening
- https://github.com/dev-sec/puppet-postgres-hardening

## Standalone Usage

This Compliance Profile requires [InSpec](https://github.com/chef/inspec) for execution:

```
$ git clone https://github.com/dev-sec/postgres-baseline
$ inspec exec postgres-baseline
```

You can also execute the profile directly from Github:

```
$ inspec exec https://github.com/dev-sec/postgres-baseline
```

## License and Author

- Author:: Patrick Muench <patrick.muench1111@gmail.com >
- Author:: Dominik Richter <dominik.richter@googlemail.com>
- Author:: Christoph Hartmann <chris@lollyrock.com>
- Author:: Edmund Haselwanter <me@ehaselwanter.com>

- Copyright 2014-2022, The DevSec Hardening Framework Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
