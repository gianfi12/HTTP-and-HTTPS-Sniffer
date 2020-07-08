-module(sniff).
-behaviour(gen_fsm).

-include_lib("package/pkt/include/pkt.hrl").

% Interface
-export([start/0, start/1, stop/0]).
-export([start_link/0]).
% States
-export([waiting/2, sniffing/2]).
% Behaviours
-export([init/1, handle_event/3, handle_sync_event/4,
        handle_info/3, terminate/3, code_change/4]).

-define(is_print(C), C >= $\s, C =< $~).

-record(state, {
        pid,
        crash = true,
        format = [] % full packet dump: binary, hex
        }).


%%--------------------------------------------------------------------
%%% Interface
%%--------------------------------------------------------------------
start() ->
    start([{filter, "tcp and port 80"},
            {chroot, "priv/tmp"}]).
start(Opt) when is_list(Opt) ->
    gen_fsm:send_event(?MODULE, {start, Opt}).

stop() ->
    gen_fsm:send_event(?MODULE, stop).


%%--------------------------------------------------------------------
%%% Callbacks
%%--------------------------------------------------------------------
start_link() ->
    gen_fsm:start({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    process_flag(trap_exit, true),
    {ok, waiting, #state{}}.

handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    {next_state, StateName, State}.


%%
%% State: sniffing
%%
handle_info({packet, DLT, Time, Len, Data}, sniffing,
    #state{format = Format} = State) ->
    io:format("~p~n", [Data]);
    %%Packet = decode(DLT, Data, State),
    %%Headers = header(Packet),

% epcap port stopped
handle_info({'EXIT', _Pid, normal}, sniffing, State) ->
    {next_state, sniffing, State};

%%
%% State: waiting
%%

% epcap port stopped
handle_info({'EXIT', _Pid, normal}, waiting, State) ->
    {next_state, waiting, State}.

terminate(_Reason, _StateName, _State) ->
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.


%%--------------------------------------------------------------------
%%% States
%%--------------------------------------------------------------------
waiting({start, Opt}, State) ->
    Format = proplists:get_value(format, Opt, []),
    Snaplen = proplists:get_value(snaplen, Opt),
    {ok, Pid} = epcap:start_link(Opt),
    {next_state, sniffing, State#state{
            pid = Pid,
            format = Format,
            crash = Snaplen =:= undefined
        }}.

sniffing({start, Opt}, #state{pid = Pid} = State) ->
    epcap:stop(Pid),
    {ok, Pid1} = epcap:start_link(Opt),
    {next_state, sniffing, State#state{pid = Pid1}};
sniffing(stop, #state{pid = Pid} = State) ->
    epcap:stop(Pid),
    {next_state, waiting, State}.


%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------


