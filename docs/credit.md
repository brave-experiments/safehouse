# Credit

Ali Shahin Shamsabadi, Brian R. Bondy, and Brendan Eich developed the idea behind this
project: that indirect prompt injection can be made structurally impossible rather than
merely unlikely, by enforcing information-flow labels at every boundary and separating
routing from content so untrusted text cannot redirect an action.

Ali took the idea considerably further, working out the enforcement model in detail and
building the first prototype of it in this repository.

Brian masterfully productionized SafeHouse into
[brave-user-agent](https://github.com/brave-experiments/brave-user-agent), which applies
that model to a coding agent.
